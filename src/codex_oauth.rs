use crate::vault::{SecretMeta, SecretRef, VaultRuntime};
use reqwest::blocking::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use serde_json::Value;
use std::io::Read;
use std::time::Duration;

const CODEX_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CODEX_OAUTH_TOKEN_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
const CODEX_OAUTH_REFRESH_SKEW_MS: i64 = 10 * 60 * 1000;
const CODEX_DEFAULT_EXPIRES_IN_SECONDS: i64 = 60 * 60;
const CODEX_OAUTH_HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const CODEX_OAUTH_MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A short-lived OAuth lease for trusted native host code embedding aivault.
///
/// This API is intentionally not exposed through the CLI or daemon. It keeps
/// provider-account bootstrap out of the capability surface available to
/// generated apps while preserving aivault as the refresh-token owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexOAuthAccess {
    pub access_token: String,
    pub account_id: String,
    pub email: Option<String>,
    pub expires_at_ms: i64,
}

pub fn prepare_codex_oauth_access(
    vault: &VaultRuntime,
    secret_ref: &str,
) -> Result<CodexOAuthAccess, String> {
    let value = prepare_codex_oauth_value(vault, secret_ref, None)?;
    let access_token = value_string_field(&value, &["access_token", "accessToken"])
        .ok_or_else(|| "CODEX_OAUTH_JSON is missing access_token".to_string())?;
    let account_id = value_string_field(&value, &["account_id", "accountId"])
        .ok_or_else(|| "CODEX_OAUTH_JSON is missing account_id".to_string())?;
    Ok(CodexOAuthAccess {
        access_token,
        account_id,
        email: value_string_field(&value, &["email"]),
        expires_at_ms: codex_oauth_expires_ms(&value),
    })
}

pub(crate) fn prepare_codex_oauth_value(
    vault: &VaultRuntime,
    secret_ref: &str,
    rejected_access_token: Option<&str>,
) -> Result<Value, String> {
    let parsed = SecretRef::parse(secret_ref)?;
    // The native host, CLI, and multiple daemons share rotating credentials.
    // Reread only after locking, and retain the lock through durable writeback.
    let _refresh_lock =
        crate::file_lock::lock(vault.paths().root_dir(), "codex-refresh", &parsed.secret_id)
            .map_err(|error| error.to_string())?;
    let (meta, value) = read_codex_oauth_secret_value(vault, secret_ref)?;
    check_refresh_failure(&value)?;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let current_access = value_string_field(&value, &["access_token", "accessToken"]);
    let rejected_current =
        rejected_access_token.is_some() && rejected_access_token == current_access.as_deref();
    if !rejected_current && codex_oauth_expires_ms(&value) > now_ms + CODEX_OAUTH_REFRESH_SKEW_MS {
        return Ok(value);
    }

    let (updated, failure) = match refresh_codex_oauth_secret(&value) {
        Ok(updated) => (updated, None),
        Err(RefreshError::Permanent(failure)) => {
            let mut updated = value.clone();
            updated["refresh_error"] = serde_json::to_value(&failure).map_err(|e| e.to_string())?;
            (updated, Some(failure))
        }
        Err(RefreshError::Transient(error)) => return Err(error),
    };
    let bytes = serde_json::to_vec(&updated).map_err(|error| error.to_string())?;
    if vault
        .rotate_secret_value_if_version(&meta.secret_id, &bytes, Some(meta.value_version))
        .map_err(|error| error.to_string())?
        .is_none()
    {
        // A reconnect may complete while the upstream request is in flight.
        // Neither its new token nor its healthy state may be overwritten.
        let (_, current) = read_codex_oauth_secret_value(vault, secret_ref)?;
        check_refresh_failure(&current)?;
        return if codex_oauth_expires_ms(&current) > chrono::Utc::now().timestamp_millis() {
            Ok(current)
        } else {
            Err("ChatGPT credentials changed during refresh; retry the request".to_string())
        };
    }
    if let Some(failure) = failure {
        return Err(failure.to_string());
    }
    Ok(updated)
}

fn value_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn codex_oauth_expires_ms(value: &Value) -> i64 {
    value
        .get("expires")
        .or_else(|| value.get("expires_at"))
        .or_else(|| value.get("expiresMs"))
        .or_else(|| value.get("accessTokenExpiresAtMs"))
        .and_then(Value::as_i64)
        .unwrap_or(i64::MIN)
}

fn read_codex_oauth_secret_value(
    vault: &VaultRuntime,
    secret_ref: &str,
) -> Result<(SecretMeta, Value), String> {
    let (meta, raw) = vault
        .resolve_secret_ref_snapshot(
            secret_ref,
            Some("secret.codex_oauth.native_lease"),
            Some("moldable-desktop"),
        )
        .map_err(|error| error.to_string())?;
    if meta.name != "CODEX_OAUTH_JSON" || meta.revoked_at_ms.is_some() {
        return Err("secret ref is not an active CODEX_OAUTH_JSON credential".to_string());
    }
    let value =
        serde_json::from_slice(&raw).map_err(|_| "CODEX_OAUTH_JSON must be JSON".to_string())?;
    Ok((meta, value))
}

fn refresh_codex_oauth_secret(value: &Value) -> Result<Value, RefreshError> {
    let refresh_token = value_string_field(value, &["refresh_token", "refreshToken"])
        .ok_or_else(|| "CODEX_OAUTH_JSON is expired and missing refresh_token".to_string())?;
    let token_url = reqwest::Url::parse(&codex_oauth_token_endpoint())
        .map_err(|_| "invalid Codex OAuth token endpoint url".to_string())?;
    let is_loopback = token_url
        .host_str()
        .is_some_and(|host| host == "127.0.0.1" || host == "localhost");
    if token_url.scheme() != "https"
        && !(cfg!(debug_assertions)
            && token_url.scheme() == "http"
            && is_loopback
            && dev_flag_true("AIVAULT_DEV_ALLOW_HTTP_LOCAL"))
    {
        return Err("Codex OAuth token endpoint must use https"
            .to_string()
            .into());
    }

    let client = Client::builder()
        .redirect(RedirectPolicy::none())
        .timeout(CODEX_OAUTH_HTTP_TIMEOUT)
        .build()
        .map_err(|error| error.to_string())?;
    let mut response = client
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", CODEX_OAUTH_CLIENT_ID),
        ])
        .send()
        .map_err(|error| format!("Codex OAuth token refresh failed: {error}"))?;

    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > CODEX_OAUTH_MAX_RESPONSE_BYTES as u64)
    {
        return Err("Codex OAuth token response is too large".to_string().into());
    }
    let mut body_bytes = Vec::new();
    response
        .by_ref()
        .take((CODEX_OAUTH_MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut body_bytes)
        .map_err(|error| error.to_string())?;
    if body_bytes.len() > CODEX_OAUTH_MAX_RESPONSE_BYTES {
        return Err("Codex OAuth token response is too large".to_string().into());
    }
    if !status.is_success() {
        if let Some(failure) = RefreshFailure::from_response(status.as_u16(), &body_bytes) {
            return Err(RefreshError::Permanent(failure));
        }
        return Err(format!("Codex OAuth token endpoint returned {}", status.as_u16()).into());
    }

    let json: Value = serde_json::from_slice(&body_bytes)
        .map_err(|_| "Codex OAuth token response must be JSON".to_string())?;
    let access_token = value_string_field(&json, &["access_token"])
        .ok_or_else(|| "Codex OAuth token response missing access_token".to_string())?;
    let expires_in = json
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|seconds| *seconds > 0)
        .unwrap_or(CODEX_DEFAULT_EXPIRES_IN_SECONDS);
    let next_refresh_token = value_string_field(&json, &["refresh_token"]).unwrap_or(refresh_token);
    let expires_at = chrono::Utc::now()
        .timestamp_millis()
        .saturating_add(expires_in.saturating_mul(1000));

    let mut updated = value.as_object().cloned().unwrap_or_default();
    // Canonical expiry wins over legacy aliases after refresh.
    for key in [
        "expires",
        "expiresMs",
        "accessTokenExpiresAtMs",
        "refresh_error",
    ] {
        updated.remove(key);
    }
    updated.insert("access_token".to_string(), Value::String(access_token));
    updated.insert(
        "refresh_token".to_string(),
        Value::String(next_refresh_token),
    );
    updated.insert(
        "expires_at".to_string(),
        Value::Number(serde_json::Number::from(expires_at)),
    );
    for key in ["account_id", "email", "id_token"] {
        if let Some(next) =
            value_string_field(&json, &[key]).or_else(|| value_string_field(value, &[key]))
        {
            updated.insert(key.to_string(), Value::String(next));
        }
    }
    updated.insert(
        "updated_at".to_string(),
        Value::String(chrono::Utc::now().to_rfc3339()),
    );
    Ok(Value::Object(updated))
}

#[path = "codex-oauth-errors.rs"]
mod errors;
use errors::{check_refresh_failure, RefreshError, RefreshFailure};

fn codex_oauth_token_endpoint() -> String {
    #[cfg(debug_assertions)]
    if let Some(endpoint) = std::env::var("AIVAULT_DEV_CODEX_OAUTH_TOKEN_ENDPOINT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return endpoint;
    }

    CODEX_OAUTH_TOKEN_ENDPOINT.to_string()
}

#[cfg(debug_assertions)]
fn dev_flag_true(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

#[cfg(not(debug_assertions))]
fn dev_flag_true(_name: &str) -> bool {
    false
}
