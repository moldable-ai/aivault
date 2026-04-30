use std::net::IpAddr;
use std::time::Instant;

use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::broker::{Capability, ProxyEnvelope};
use crate::broker_store::{BrokerStore, StoredCredential};
use crate::provider_plugins::ProviderInvokeRequest;
use crate::vault::{append_audit_event, SecretRef, VaultAuditEvent, VaultRuntime};

const PROVIDER: &str = "postgres";
const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 1_000;
const DEFAULT_OFFSET: u64 = 0;
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MAX_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostgresSecret {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    database: Option<String>,
}

#[derive(Debug)]
struct PostgresConnectionPolicyView {
    host: String,
    port: u16,
    database: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PostgresRequest {
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    sql: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PostgresResponse<T: Serialize> {
    capability: String,
    credential: String,
    database: String,
    elapsed_ms: u128,
    result: T,
}

pub fn is_postgres_capability(id: &str) -> bool {
    id.trim().starts_with("postgres/")
}

pub fn builtin_capability(id: &str) -> Option<Capability> {
    crate::provider_plugins::postgres_capability(id)
}

pub fn builtin_capabilities() -> Vec<Capability> {
    crate::provider_plugins::postgres_capabilities()
}

pub fn run_postgres_capability(
    vault: &VaultRuntime,
    store: &BrokerStore,
    envelope: ProxyEnvelope,
    client_ip: IpAddr,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<Value, String> {
    if !client_ip.is_loopback() {
        return Err("non-loopback clients are rejected by default".to_string());
    }

    let capability = envelope.capability.trim().to_string();
    if builtin_capability(&capability).is_none() {
        return Err(format!("postgres capability '{}' not found", capability));
    }
    if !envelope.request.method.eq_ignore_ascii_case("POST") {
        return Err("postgres capabilities require POST".to_string());
    }

    let request = parse_request_body(&envelope)?;
    let credential_id = envelope
        .credential
        .as_deref()
        .or(request.credential.as_deref())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    let stored =
        resolve_postgres_credential(store, credential_id.as_deref(), workspace_id, group_id)?;
    let raw_secret = resolve_secret_ref_for_context(
        vault,
        &stored.secret_ref,
        workspace_id,
        group_id,
        Some(&capability),
        Some(&stored.id),
    )?;
    let secret_value: Value = serde_json::from_slice(&raw_secret)
        .map_err(|_| "postgres secret must be JSON".to_string())?;
    let policy_view = PostgresConnectionPolicyView::from_secret_value(&secret_value)?;
    ensure_host_allowed(stored, &policy_view)?;

    let timeout_ms = request
        .timeout_ms
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .min(MAX_TIMEOUT_MS);
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = request.offset.unwrap_or(DEFAULT_OFFSET);
    let started = Instant::now();

    let plugin_result = crate::provider_plugins::invoke_provider(
        vault,
        PROVIDER,
        &ProviderInvokeRequest {
            protocol_version: 1,
            capability: capability.clone(),
            secret: secret_value,
            request: serde_json::to_value(&request).map_err(|e| e.to_string())?,
            limit,
            offset,
            timeout_ms,
        },
    )?;

    append_audit_event(
        &vault.paths().audit_dir(),
        &VaultAuditEvent {
            ts_ms: Utc::now().timestamp_millis(),
            kind: "postgres.invoke".to_string(),
            secret_id: SecretRef::parse(&stored.secret_ref)
                .ok()
                .map(|secret_ref| secret_ref.secret_id),
            scope: workspace_id.map(|ws| {
                group_id
                    .map(|group| format!("group:{ws}:{group}"))
                    .unwrap_or_else(|| format!("workspace:{ws}"))
            }),
            actor: Some("aivault-cli".to_string()),
            capability: Some(capability.clone()),
            consumer: Some(stored.id.clone()),
            note: Some(format!(
                "postgres provider invocation rowsLimit={} offset={} timeoutMs={} host={}",
                limit,
                offset,
                timeout_ms,
                policy_view.authority()
            )),
        },
    )?;

    let payload = PostgresResponse {
        capability: capability.clone(),
        credential: stored.id.clone(),
        database: policy_view.database,
        elapsed_ms: started.elapsed().as_millis(),
        result: plugin_result,
    };

    response_envelope(&capability, &stored.id, &payload)
}

fn parse_request_body(envelope: &ProxyEnvelope) -> Result<PostgresRequest, String> {
    let Some(body) = envelope.request.body.as_deref() else {
        return Ok(PostgresRequest::default());
    };
    if body.trim().is_empty() {
        return Ok(PostgresRequest::default());
    }
    serde_json::from_str(body).map_err(|e| format!("postgres request body must be JSON: {}", e))
}

fn resolve_postgres_credential<'a>(
    store: &'a BrokerStore,
    requested_id: Option<&str>,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<&'a StoredCredential, String> {
    let matching: Vec<&StoredCredential> = store
        .credentials()
        .iter()
        .filter(|credential| credential.provider == PROVIDER)
        .filter(|credential| credential_matches_context(credential, workspace_id, group_id))
        .collect();

    if let Some(id) = requested_id {
        return matching
            .into_iter()
            .find(|credential| credential.id == id)
            .ok_or_else(|| format!("postgres credential '{}' not found in this context", id));
    }

    match matching.as_slice() {
        [only] => Ok(*only),
        [] => Err("no postgres credential found in this context".to_string()),
        _ => Err("multiple postgres credentials available; pass credential id".to_string()),
    }
}

fn credential_matches_context(
    credential: &StoredCredential,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> bool {
    let ws = workspace_id.map(str::trim).filter(|v| !v.is_empty());
    let group_id = group_id.map(str::trim).filter(|v| !v.is_empty());
    if group_id.is_some() && ws.is_none() {
        return false;
    }

    let cred_ws = credential
        .workspace_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let cred_group_id = credential
        .group_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if ws.is_none() && group_id.is_none() {
        return cred_ws.is_none() && cred_group_id.is_none();
    }
    if let Some(cred_ws) = cred_ws {
        if ws != Some(cred_ws) {
            return false;
        }
        if let Some(cred_group_id) = cred_group_id {
            return group_id == Some(cred_group_id);
        }
        return true;
    }
    true
}

fn resolve_secret_ref_for_context(
    vault: &VaultRuntime,
    secret_ref: &str,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
    capability: Option<&str>,
    consumer: Option<&str>,
) -> Result<Vec<u8>, String> {
    let ws = workspace_id.map(str::trim).filter(|v| !v.is_empty());
    let group_id = group_id.map(str::trim).filter(|v| !v.is_empty());
    if group_id.is_some() && ws.is_none() {
        return Err("--workspace-id is required when --group-id is provided".to_string());
    }
    if let (Some(ws), Some(group_id)) = (ws, group_id) {
        return vault
            .resolve_secret_ref_for_group(secret_ref, ws, group_id, capability, consumer)
            .map_err(|e| e.to_string());
    }
    vault
        .resolve_secret_ref(secret_ref, capability, consumer)
        .map_err(|e| e.to_string())
}

impl PostgresConnectionPolicyView {
    fn from_secret_value(value: &Value) -> Result<Self, String> {
        let secret: PostgresSecret = serde_json::from_value(value.clone())
            .map_err(|_| "postgres secret must be JSON".to_string())?;
        if let Some(url) = secret
            .url
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            let parsed =
                reqwest::Url::parse(url).map_err(|e| format!("invalid postgres url: {}", e))?;
            if parsed.scheme() != "postgresql" && parsed.scheme() != "postgres" {
                return Err("postgres url must use postgres:// or postgresql://".to_string());
            }
            let host = parsed
                .host_str()
                .ok_or_else(|| "postgres url host is required".to_string())?
                .to_string();
            let database = parsed.path().trim_start_matches('/').to_string();
            if database.is_empty() {
                return Err("postgres url database is required".to_string());
            }
            return Ok(Self {
                host,
                port: parsed.port().unwrap_or(5432),
                database,
            });
        }

        let host = required(secret.host, "host")?;
        let database = required(secret.database, "database")?;
        Ok(Self {
            host,
            port: secret.port.unwrap_or(5432),
            database,
        })
    }

    fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn required(value: Option<String>, label: &str) -> Result<String, String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("postgres secret {} is required", label))
}

fn ensure_host_allowed(
    stored: &StoredCredential,
    connection: &PostgresConnectionPolicyView,
) -> Result<(), String> {
    let authority = connection.authority();
    if stored.hosts.is_empty() {
        return Err("postgres credential must include at least one allowed host".to_string());
    }
    if stored.hosts.iter().any(|pattern| {
        crate::broker::host_matches(pattern, &authority)
            || crate::broker::host_matches(pattern, &connection.host)
    }) {
        return Ok(());
    }
    Err("postgres credential host is not allowed by credential policy".to_string())
}

fn response_envelope<T: Serialize>(
    capability: &str,
    credential: &str,
    payload: &T,
) -> Result<Value, String> {
    let body = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let body_utf8 = String::from_utf8(body.clone()).ok();
    Ok(serde_json::json!({
        "planned": {
            "capability": capability,
            "credential": credential,
            "method": "POST",
            "url": "postgres://provider/"
        },
        "request": {
            "capability": capability,
            "credential": credential,
            "host": "postgres",
            "scheme": "postgres",
            "method": "POST",
            "path": "/"
        },
        "response": {
            "status": 200,
            "headers": [],
            "bodyUtf8": body_utf8,
            "bodyB64": base64::engine::general_purpose::STANDARD.encode(body)
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_url_secret_parses_connection_without_query_metadata() {
        let conn = PostgresConnectionPolicyView::from_secret_value(&serde_json::json!({
            "url": "postgresql://postgres:postgres@localhost:5434/shippy?statusColor=DAEBC2"
        }))
        .unwrap();

        assert_eq!(conn.host, "localhost");
        assert_eq!(conn.port, 5434);
        assert_eq!(conn.database, "shippy");
    }

    #[test]
    fn postgres_url_secret_parses_remote_hosts() {
        let conn = PostgresConnectionPolicyView::from_secret_value(&serde_json::json!({
            "url": "postgresql://app%40user:p%40ss@db.example.com:6543/app_prod?sslmode=require"
        }))
        .unwrap();

        assert_eq!(conn.host, "db.example.com");
        assert_eq!(conn.port, 6543);
        assert_eq!(conn.database, "app_prod");
    }
}
