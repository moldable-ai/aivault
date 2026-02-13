use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use base64::Engine;
use chrono::Utc;

use super::{
    AuthStrategy, BrokerError, BrokerResult, ErrorCode, Header, MultipartFile,
    ProxyEnvelopeRequest, RequestBodyMode, SecretMaterial,
};

const BROKER_MULTIPART_BOUNDARY: &str = "aivault-boundary";

pub(super) fn normalize_hosts(hosts: Vec<String>) -> BrokerResult<Vec<String>> {
    let mut set = HashSet::new();
    let mut out = Vec::new();
    for host in hosts {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            continue;
        }
        if set.insert(host.clone()) {
            out.push(host);
        }
    }
    if out.is_empty() {
        return Err(BrokerError::new(
            ErrorCode::PolicyViolation,
            "credential hosts are required",
        ));
    }
    Ok(out)
}

pub(super) fn validate_host_pattern(host: &str, core_exact_hosts_only: bool) -> BrokerResult<()> {
    let normalized = host.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(BrokerError::new(
            ErrorCode::PolicyViolation,
            "host cannot be empty",
        ));
    }

    if normalized.starts_with("*.") {
        if core_exact_hosts_only {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "wildcard hosts are invalid for core conformance",
            ));
        }
        if normalized.matches('*').count() != 1 {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "invalid wildcard host pattern",
            ));
        }
        if normalized.split('.').count() < 3 {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "wildcard must include at least one suffix label",
            ));
        }
    } else if normalized.contains('*') {
        return Err(BrokerError::new(
            ErrorCode::PolicyViolation,
            "wildcards are only allowed as leading *.",
        ));
    }

    Ok(())
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        if host == suffix {
            return false;
        }
        return host.ends_with(&format!(".{}", suffix));
    }

    host == pattern
}

pub(super) fn is_ssrf_blocked_host(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();

    if matches!(host.as_str(), "localhost" | "metadata.google.internal") {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.octets() == [169, 254, 169, 254]
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        };
    }

    false
}

pub(super) fn normalize_method(method: &str) -> String {
    method.trim().to_ascii_uppercase()
}

pub(super) fn method_allowed(allowed: &[String], method: &str) -> bool {
    allowed
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(method))
}

pub(super) fn path_allowed(prefixes: &[String], path: &str) -> bool {
    prefixes.iter().any(|prefix| path.starts_with(prefix))
}

pub(super) fn longest_prefix_len(prefixes: &[String], path: &str) -> usize {
    prefixes
        .iter()
        .filter(|prefix| path.starts_with(prefix.as_str()))
        .map(|prefix| prefix.len())
        .max()
        .unwrap_or(0)
}

pub(super) fn normalize_path_and_query(
    path: &str,
) -> BrokerResult<(String, Vec<(String, String)>)> {
    let trimmed = path.trim();
    if !trimmed.starts_with('/') {
        return Err(BrokerError::new(
            ErrorCode::InvalidRequest,
            "request.path must start with '/'",
        ));
    }

    let (path_only, query_raw) = match trimmed.split_once('?') {
        Some((p, q)) => (p, q),
        None => (trimmed, ""),
    };

    if path_has_traversal(path_only) {
        return Err(BrokerError::new(
            ErrorCode::PolicyViolation,
            "path traversal is not allowed",
        ));
    }

    let query = parse_query(query_raw);
    Ok((path_only.to_string(), query))
}

fn path_has_traversal(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") {
        return true;
    }
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

fn parse_query(raw: &str) -> Vec<(String, String)> {
    if raw.trim().is_empty() {
        return Vec::new();
    }

    raw.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (k.to_string(), v.to_string())
        })
        .collect()
}

pub(super) fn ensure_method_allowed(allowed: &[String], method: &str) -> BrokerResult<()> {
    if method_allowed(allowed, method) {
        return Ok(());
    }
    Err(BrokerError::new(
        ErrorCode::PolicyViolation,
        "method not allowed by capability",
    ))
}

pub(super) fn ensure_path_allowed(prefixes: &[String], path: &str) -> BrokerResult<()> {
    if path_allowed(prefixes, path) {
        return Ok(());
    }
    Err(BrokerError::new(
        ErrorCode::PolicyViolation,
        "path not allowed by capability",
    ))
}

pub(super) fn resolve_body_mode(request: &ProxyEnvelopeRequest) -> BrokerResult<RequestBodyMode> {
    let has_text = request.body.is_some();
    let has_multipart = request.multipart.is_some() || !request.multipart_files.is_empty();
    let has_body_file = request.body_file_path.is_some();

    let set_count = [has_text, has_multipart, has_body_file]
        .into_iter()
        .filter(|v| *v)
        .count();

    if set_count > 1 {
        return Err(BrokerError::new(
            ErrorCode::PolicyViolation,
            "multiple body modes are not allowed",
        ));
    }

    if let Some(text) = &request.body {
        return Ok(RequestBodyMode::Text(text.clone()));
    }

    if has_multipart {
        let fields = request.multipart.clone().unwrap_or_default();
        let files = request
            .multipart_files
            .iter()
            .map(|f| MultipartFile {
                field: f.field.clone(),
                path: f.path.clone(),
            })
            .collect();
        return Ok(RequestBodyMode::Multipart { fields, files });
    }

    if let Some(path) = &request.body_file_path {
        return Ok(RequestBodyMode::BodyFilePath(path.clone()));
    }

    Ok(RequestBodyMode::Empty)
}

pub(super) fn estimated_body_size_bytes(body_mode: &RequestBodyMode) -> BrokerResult<usize> {
    match body_mode {
        RequestBodyMode::Empty => Ok(0),
        RequestBodyMode::Text(text) => Ok(text.len()),
        RequestBodyMode::Multipart { fields, files } => {
            let mut total = 0usize;
            for (key, value) in fields {
                total = total.saturating_add(key.len());
                total = total.saturating_add(value.len());
            }
            for file in files {
                total = total.saturating_add(file.field.len());
                let size = std::fs::metadata(Path::new(&file.path))
                    .map(|m| m.len() as usize)
                    .map_err(|_| {
                        BrokerError::new(
                            ErrorCode::InvalidRequest,
                            "multipart file path not accessible",
                        )
                    })?;
                total = total.saturating_add(size);
            }
            Ok(total)
        }
        RequestBodyMode::BodyFilePath(path) => {
            let size = std::fs::metadata(Path::new(path))
                .map(|m| m.len() as usize)
                .map_err(|_| {
                    BrokerError::new(ErrorCode::InvalidRequest, "bodyFilePath not accessible")
                })?;
            Ok(size)
        }
    }
}

pub(super) fn apply_broker_managed_body_headers(
    headers: &mut Vec<Header>,
    body_mode: &RequestBodyMode,
) {
    if !matches!(body_mode, RequestBodyMode::Multipart { .. }) {
        return;
    }

    headers.retain(|header| !header.name.eq_ignore_ascii_case("content-type"));
    headers.push(Header {
        name: "content-type".to_string(),
        value: format!(
            "multipart/form-data; boundary={}",
            BROKER_MULTIPART_BOUNDARY
        ),
    });
}

pub(super) fn sanitize_headers(
    headers: &[Header],
    auth: &AuthStrategy,
) -> BrokerResult<Vec<Header>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let credential_auth_header = match auth {
        AuthStrategy::Header { header_name, .. } => Some(header_name.to_ascii_lowercase()),
        AuthStrategy::Hmac { header_name, .. } => Some(header_name.to_ascii_lowercase()),
        _ => None,
    };

    for header in headers {
        let name = header.name.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }

        if is_reserved_header(&name) {
            continue;
        }

        if is_auth_class_header(&name)
            || credential_auth_header
                .as_deref()
                .is_some_and(|expected| expected == name)
        {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "caller-supplied auth headers are not allowed",
            ));
        }

        if !seen.insert(name.clone()) {
            return Err(BrokerError::new(
                ErrorCode::PolicyViolation,
                "duplicate headers are not allowed",
            ));
        }

        out.push(Header {
            name,
            value: header.value.clone(),
        });
    }

    Ok(out)
}

fn is_reserved_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    ) || name.starts_with("sec-websocket-")
}

pub(super) fn is_hop_by_hop_header(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    is_reserved_header(&normalized)
}

fn is_auth_class_header(name: &str) -> bool {
    matches!(name, "authorization" | "proxy-authorization")
}

pub(super) fn apply_auth(
    auth: &AuthStrategy,
    secret: Option<&SecretMaterial>,
    headers: &mut Vec<Header>,
    query: &mut Vec<(String, String)>,
    envelope_mode: bool,
    method: &str,
    path: &str,
) -> BrokerResult<()> {
    match auth {
        AuthStrategy::Header {
            header_name,
            value_template,
        } => {
            let secret = match secret {
                Some(SecretMaterial::String(value)) => value,
                _ => {
                    return Err(BrokerError::new(
                        ErrorCode::VaultUnavailable,
                        "missing string secret for header auth",
                    ));
                }
            };
            headers.push(Header {
                name: header_name.to_ascii_lowercase(),
                value: value_template.replace("{{secret}}", secret),
            });
        }
        AuthStrategy::Query { param_name } => {
            let secret = match secret {
                Some(SecretMaterial::String(value)) => value,
                _ => {
                    return Err(BrokerError::new(
                        ErrorCode::VaultUnavailable,
                        "missing string secret for query auth",
                    ));
                }
            };

            if envelope_mode && query.iter().any(|(k, _)| k == param_name) {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "query auth parameter is broker-managed",
                ));
            }

            if !envelope_mode {
                query.retain(|(k, _)| k != param_name);
            }

            query.push((param_name.clone(), secret.clone()));
        }
        AuthStrategy::Basic => {
            let (username, password) = match secret {
                Some(SecretMaterial::Basic { username, password }) => (username, password),
                _ => {
                    return Err(BrokerError::new(
                        ErrorCode::VaultUnavailable,
                        "missing username/password secret for basic auth",
                    ));
                }
            };
            let token = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", username, password));
            headers.push(Header {
                name: "authorization".to_string(),
                value: format!("Basic {}", token),
            });
        }
        AuthStrategy::OAuth2 {
            grant_type,
            token_endpoint,
            scopes,
        } => {
            if !oauth_grant_is_supported(grant_type) {
                return Err(BrokerError::new(
                    ErrorCode::PolicyViolation,
                    "oauth2 consent/setup flow must happen outside broker",
                ));
            }
            let oauth = match secret {
                Some(SecretMaterial::OAuth2 {
                    client_id,
                    client_secret,
                    access_token,
                    access_token_expires_at_ms,
                    refresh_token,
                    ..
                }) => {
                    if access_token.as_deref().is_some_and(|_| {
                        access_token_expires_at_ms
                            .is_some_and(|expires| expires > Utc::now().timestamp_millis())
                    }) {
                        access_token.clone().unwrap_or_default()
                    } else if grant_type.eq_ignore_ascii_case("client_credentials") {
                        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
                            return Err(BrokerError::new(
                                ErrorCode::VaultUnavailable,
                                "missing oauth2 client credentials",
                            ));
                        }
                        if scopes.is_empty() {
                            format!("refreshed:client_credentials:{}", client_id)
                        } else {
                            format!(
                                "refreshed:client_credentials:{}:scopes={}",
                                client_id,
                                scopes.join(" ")
                            )
                        }
                    } else {
                        if refresh_token.trim().is_empty() {
                            return Err(BrokerError::new(
                                ErrorCode::VaultUnavailable,
                                "missing oauth2 refresh token",
                            ));
                        }
                        if scopes.is_empty() {
                            format!("refreshed:{}:{}", grant_type, refresh_token)
                        } else {
                            format!(
                                "refreshed:{}:{}:scopes={}",
                                grant_type,
                                refresh_token,
                                scopes.join(" ")
                            )
                        }
                    }
                }
                _ => {
                    return Err(BrokerError::new(
                        ErrorCode::VaultUnavailable,
                        format!("missing oauth2 secret for endpoint {}", token_endpoint),
                    ));
                }
            };
            headers.push(Header {
                name: "authorization".to_string(),
                value: format!("Bearer {}", oauth),
            });
        }
        AuthStrategy::AwsSigV4 { service, region } => {
            let aws = match secret {
                Some(SecretMaterial::Aws {
                    access_key_id,
                    secret_access_key,
                    session_token,
                }) => (access_key_id, secret_access_key, session_token),
                _ => {
                    return Err(BrokerError::new(
                        ErrorCode::VaultUnavailable,
                        "missing aws credentials",
                    ));
                }
            };
            let mut value = format!(
                "AWS4-HMAC-SHA256 Credential={}/{}/{}/aws4_request",
                aws.0, region, service
            );
            if let Some(token) = aws.2 {
                value.push_str(&format!(", SessionToken={}", token));
            }
            headers.push(Header {
                name: "authorization".to_string(),
                value,
            });
        }
        AuthStrategy::Hmac {
            algorithm,
            header_name,
            value_template,
        } => {
            let secret = match secret {
                Some(SecretMaterial::Hmac { secret }) => secret,
                _ => {
                    return Err(BrokerError::new(
                        ErrorCode::VaultUnavailable,
                        "missing hmac secret",
                    ));
                }
            };
            let canonical = canonical_hmac_signing_input(method, path, query);
            let fake_sig = format!("{}:{}:{}", algorithm, secret, canonical);
            headers.push(Header {
                name: header_name.to_ascii_lowercase(),
                value: value_template.replace("{{signature}}", &fake_sig),
            });
        }
        AuthStrategy::Mtls => {
            let (cert_pem, key_pem) = match secret {
                Some(SecretMaterial::Mtls { cert_pem, key_pem }) => (cert_pem, key_pem),
                _ => {
                    return Err(BrokerError::new(
                        ErrorCode::VaultUnavailable,
                        "missing mtls cert/key",
                    ));
                }
            };
            headers.push(Header {
                name: "x-client-cert-sha".to_string(),
                value: format!("{}:{}", cert_pem.len(), key_pem.len()),
            });
        }
    }
    Ok(())
}

pub(super) fn parse_passthrough_path(path: &str) -> BrokerResult<(&str, &str)> {
    let trimmed = path.trim();
    if !trimmed.starts_with("/v/") {
        return Err(BrokerError::new(
            ErrorCode::InvalidRequest,
            "passthrough path must start with /v/{credential}/",
        ));
    }

    let rest = &trimmed[3..];
    let mut parts = rest.splitn(2, '/');
    let credential = parts.next().unwrap_or_default();
    let tail = parts.next().unwrap_or_default();

    if credential.trim().is_empty() || tail.trim().is_empty() {
        return Err(BrokerError::new(
            ErrorCode::InvalidRequest,
            "passthrough path must include credential and upstream path",
        ));
    }

    Ok((credential, &trimmed[(3 + credential.len())..]))
}

fn canonical_query_string(query: &[(String, String)]) -> String {
    let mut parts: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.sort();
    parts.join("&")
}

fn canonical_hmac_signing_input(method: &str, path: &str, query: &[(String, String)]) -> String {
    format!(
        "{}\n{}\n{}",
        normalize_method(method),
        path.trim(),
        canonical_query_string(query)
    )
}

pub(super) fn oauth_grant_is_supported(grant_type: &str) -> bool {
    matches!(
        grant_type.trim().to_ascii_lowercase().as_str(),
        "refresh_token" | "client_credentials"
    )
}

pub(super) fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
