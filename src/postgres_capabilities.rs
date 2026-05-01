use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
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
const DEFAULT_MAX_AFFECTED_ROWS: u64 = 100;
const MAX_AFFECTED_ROWS: u64 = 1_000;
const DEFAULT_MAX_EXPORT_BYTES: usize = 1_048_576;
const MAX_EXPORT_BYTES: usize = 10_485_760;
const DEFAULT_MAX_IMPORT_BYTES: usize = 1_048_576;
const MAX_IMPORT_BYTES: usize = 10_485_760;
const DEFAULT_MAX_IMPORT_ROWS: u64 = 1_000;
const MAX_IMPORT_ROWS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PostgresPolicyMode {
    ReadOnly,
    Write,
    Admin,
}

impl PostgresPolicyMode {
    fn parse(raw: Option<&str>) -> Result<Self, String> {
        let normalized = raw
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("read-only");

        match normalized.to_ascii_lowercase().as_str() {
            "read-only" | "readonly" | "read_only" => Ok(Self::ReadOnly),
            "write" => Ok(Self::Write),
            "admin" => Ok(Self::Admin),
            _ => Err(format!("unsupported postgres policy mode '{}'", normalized)),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
}

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
    #[serde(default)]
    policy_mode: Option<String>,
    #[serde(default)]
    max_affected_rows: Option<u64>,
    #[serde(default)]
    max_export_bytes: Option<usize>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    source_content: Option<String>,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    columns: Option<Vec<String>>,
    #[serde(default)]
    max_import_bytes: Option<usize>,
    #[serde(default)]
    max_rows: Option<u64>,
    #[serde(default)]
    header: Option<bool>,
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

    let mut request = parse_request_body(&envelope)?;
    let requested_policy_mode =
        requested_policy_mode_for_capability(&capability, request.policy_mode.as_deref())?;
    let credential_id = envelope
        .credential
        .as_deref()
        .or(request.credential.as_deref())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    let stored =
        resolve_postgres_credential(store, credential_id.as_deref(), workspace_id, group_id)?;
    ensure_credential_allows_policy_mode(stored, requested_policy_mode)?;
    ensure_provider_supports_policy_mode(&capability, requested_policy_mode)?;
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
    let max_affected_rows = request
        .max_affected_rows
        .unwrap_or(DEFAULT_MAX_AFFECTED_ROWS)
        .clamp(1, MAX_AFFECTED_ROWS);
    request.max_affected_rows = Some(max_affected_rows);
    let max_export_bytes = request
        .max_export_bytes
        .unwrap_or(DEFAULT_MAX_EXPORT_BYTES)
        .clamp(1, MAX_EXPORT_BYTES);
    request.max_export_bytes = Some(max_export_bytes);
    let max_import_bytes = request
        .max_import_bytes
        .unwrap_or(DEFAULT_MAX_IMPORT_BYTES)
        .clamp(1, MAX_IMPORT_BYTES);
    request.max_import_bytes = Some(max_import_bytes);
    let max_rows = request
        .max_rows
        .unwrap_or(DEFAULT_MAX_IMPORT_ROWS)
        .clamp(1, MAX_IMPORT_ROWS);
    request.max_rows = Some(max_rows);
    if capability == "postgres/import-rows" {
        prepare_import_request(vault, &mut request, max_import_bytes)?;
    }
    let started = Instant::now();
    let provider_capability = if capability == "postgres/export-file" {
        "postgres/export-query"
    } else {
        capability.as_str()
    };

    let mut plugin_result = crate::provider_plugins::invoke_provider(
        vault,
        PROVIDER,
        &ProviderInvokeRequest {
            protocol_version: 1,
            capability: provider_capability.to_string(),
            secret: secret_value,
            request: serde_json::to_value(&request).map_err(|e| e.to_string())?,
            limit,
            offset,
            timeout_ms,
        },
    )?;
    if capability == "postgres/export-file" {
        plugin_result = write_export_file(vault, &request, plugin_result)?;
    }

    append_audit_event(
        &vault.paths().audit_dir(),
        &VaultAuditEvent {
            ts_ms: Utc::now().timestamp_millis(),
            kind: if capability == "postgres/execute"
                || capability == "postgres/import-rows"
                || capability == "postgres/admin"
            {
                "postgres.write".to_string()
            } else {
                "postgres.invoke".to_string()
            },
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
                "postgres provider invocation policyMode={} rowsLimit={} offset={} timeoutMs={} maxAffectedRows={} maxExportBytes={} maxImportBytes={} maxRows={} host={}",
                requested_policy_mode.as_str(),
                limit,
                offset,
                timeout_ms,
                max_affected_rows,
                max_export_bytes,
                max_import_bytes,
                max_rows,
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

fn requested_policy_mode_for_capability(
    capability: &str,
    raw_policy_mode: Option<&str>,
) -> Result<PostgresPolicyMode, String> {
    let mode = PostgresPolicyMode::parse(raw_policy_mode)?;
    if capability == "postgres/execute" {
        if raw_policy_mode
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(
                "postgres/execute requires explicit policyMode 'write' or 'admin'".to_string(),
            );
        }
        if mode == PostgresPolicyMode::ReadOnly {
            return Err("postgres/execute requires policyMode 'write' or 'admin'".to_string());
        }
        return Ok(mode);
    }
    if capability == "postgres/import-rows" {
        if raw_policy_mode
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(
                "postgres/import-rows requires explicit policyMode 'write' or 'admin'".to_string(),
            );
        }
        if mode == PostgresPolicyMode::ReadOnly {
            return Err("postgres/import-rows requires policyMode 'write' or 'admin'".to_string());
        }
        return Ok(mode);
    }
    if capability == "postgres/admin" {
        if raw_policy_mode
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err("postgres/admin requires explicit policyMode 'admin'".to_string());
        }
        if mode != PostgresPolicyMode::Admin {
            return Err("postgres/admin requires policyMode 'admin'".to_string());
        }
        return Ok(mode);
    }

    if mode != PostgresPolicyMode::ReadOnly {
        return Err(format!(
            "postgres read-only capability '{}' requires policyMode 'read-only'",
            capability
        ));
    }
    Ok(mode)
}

fn ensure_provider_supports_policy_mode(
    capability: &str,
    policy_mode: PostgresPolicyMode,
) -> Result<(), String> {
    match (capability, policy_mode) {
        (_, PostgresPolicyMode::ReadOnly) => Ok(()),
        ("postgres/execute", PostgresPolicyMode::Write | PostgresPolicyMode::Admin) => Ok(()),
        ("postgres/import-rows", PostgresPolicyMode::Write | PostgresPolicyMode::Admin) => Ok(()),
        ("postgres/admin", PostgresPolicyMode::Admin) => Ok(()),
        (_, PostgresPolicyMode::Write | PostgresPolicyMode::Admin) => Err(format!(
            "postgres policy mode '{}' is not supported by capability '{}'",
            policy_mode.as_str(),
            capability
        )),
    }
}

fn prepare_import_request(
    vault: &VaultRuntime,
    request: &mut PostgresRequest,
    max_import_bytes: usize,
) -> Result<(), String> {
    if request.source_content.is_some() {
        return Err(
            "postgres/import-rows does not accept caller-provided sourceContent".to_string(),
        );
    }
    let raw_path = request
        .source_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "postgres/import-rows requires sourcePath".to_string())?;
    let source_path = approved_postgres_file_path(vault, "imports", raw_path, false)?;
    let metadata = fs::metadata(&source_path).map_err(|e| {
        format!(
            "cannot read import source '{}': {}",
            source_path.display(),
            e
        )
    })?;
    if !metadata.is_file() {
        return Err("postgres/import-rows sourcePath must be a file".to_string());
    }
    if metadata.len() as usize > max_import_bytes {
        return Err(format!(
            "import source is {} bytes, exceeding maxImportBytes {}",
            metadata.len(),
            max_import_bytes
        ));
    }

    let mut file = fs::File::open(&source_path).map_err(|e| {
        format!(
            "cannot open import source '{}': {}",
            source_path.display(),
            e
        )
    })?;
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max_import_bytes as u64).saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|e| {
            format!(
                "cannot read import source '{}': {}",
                source_path.display(),
                e
            )
        })?;
    if raw.len() > max_import_bytes {
        return Err(format!(
            "import source exceeds maxImportBytes {}",
            max_import_bytes
        ));
    }
    let content = String::from_utf8(raw)
        .map_err(|_| "postgres/import-rows source file must be UTF-8".to_string())?;
    request.source_content = Some(content);
    Ok(())
}

fn write_export_file(
    vault: &VaultRuntime,
    request: &PostgresRequest,
    export_result: Value,
) -> Result<Value, String> {
    let destination = request
        .destination
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("default");
    if destination != "default" {
        return Err(
            "postgres/export-file currently supports destination 'default' only".to_string(),
        );
    }
    let format = export_result
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| "export result missing format".to_string())?;
    let content = export_result
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| "export result missing content".to_string())?;
    let row_count = export_result
        .get("rowCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let byte_count = content.len();
    let filename = request
        .filename
        .as_deref()
        .map(sanitize_export_filename)
        .transpose()?
        .unwrap_or_else(|| {
            format!(
                "postgres-export-{}.{}",
                Utc::now().format("%Y%m%d-%H%M%S"),
                format
            )
        });
    let filename = ensure_export_extension(&filename, format)?;
    let path = approved_postgres_file_path(vault, "exports", &filename, true)?;
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("postgres-export"),
        uuid::Uuid::new_v4()
    ));
    {
        let mut file = fs::File::create(&tmp)
            .map_err(|e| format!("cannot create export file '{}': {}", tmp.display(), e))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("cannot write export file '{}': {}", tmp.display(), e))?;
        let _ = file.sync_all();
    }
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("cannot finalize export file '{}': {}", path.display(), e)
    })?;

    Ok(serde_json::json!({
        "path": path.display().to_string(),
        "destination": destination,
        "filename": filename,
        "format": format,
        "bytes": byte_count,
        "rowCount": row_count,
        "limit": export_result.get("limit").cloned().unwrap_or(Value::Null),
        "offset": export_result.get("offset").cloned().unwrap_or(Value::Null),
        "executionMs": export_result.get("executionMs").cloned().unwrap_or(Value::Null),
        "command": "EXPORT FILE",
        "readOnly": true
    }))
}

fn approved_postgres_file_path(
    vault: &VaultRuntime,
    kind: &str,
    raw_path: &str,
    allow_missing: bool,
) -> Result<PathBuf, String> {
    let root = postgres_file_root(vault, kind)?;
    let candidate = PathBuf::from(raw_path);
    let path = if candidate.is_absolute() {
        candidate
    } else {
        root.join(candidate)
    };
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::Prefix(_)
        )
    }) {
        return Err(format!(
            "postgres {} path cannot contain parent components",
            kind
        ));
    }
    if allow_missing {
        let parent = path
            .parent()
            .ok_or_else(|| format!("postgres {} path must include a parent directory", kind))?;
        let parent = parent.canonicalize().map_err(|e| {
            format!(
                "invalid postgres {} directory '{}': {}",
                kind,
                parent.display(),
                e
            )
        })?;
        if !parent.starts_with(&root) {
            return Err(format!(
                "postgres {} path must be under '{}'",
                kind,
                root.display()
            ));
        }
        return Ok(parent.join(
            path.file_name()
                .ok_or_else(|| format!("postgres {} path must include a file name", kind))?,
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("invalid postgres {} path '{}': {}", kind, path.display(), e))?;
    if !canonical.starts_with(&root) {
        return Err(format!(
            "postgres {} path must be under '{}'",
            kind,
            root.display()
        ));
    }
    Ok(canonical)
}

fn postgres_file_root(vault: &VaultRuntime, kind: &str) -> Result<PathBuf, String> {
    let root = vault.paths().root_dir().join("postgres").join(kind);
    fs::create_dir_all(&root).map_err(|e| {
        format!(
            "cannot create postgres {} directory '{}': {}",
            kind,
            root.display(),
            e
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
    }
    root.canonicalize().map_err(|e| {
        format!(
            "cannot resolve postgres {} directory '{}': {}",
            kind,
            root.display(),
            e
        )
    })
}

fn sanitize_export_filename(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("filename cannot be empty".to_string());
    }
    if Path::new(value)
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("filename must not include path separators".to_string());
    }
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized == "." || sanitized == ".." || sanitized.is_empty() {
        return Err("filename is invalid".to_string());
    }
    Ok(sanitized)
}

fn ensure_export_extension(filename: &str, format: &str) -> Result<String, String> {
    let ext = match format {
        "csv" => "csv",
        "jsonl" => "jsonl",
        other => return Err(format!("unsupported export format '{}'", other)),
    };
    if filename.ends_with(&format!(".{}", ext)) {
        return Ok(filename.to_string());
    }
    Ok(format!("{}.{}", filename.trim_end_matches('.'), ext))
}

fn ensure_credential_allows_policy_mode(
    credential: &StoredCredential,
    requested: PostgresPolicyMode,
) -> Result<(), String> {
    let max = PostgresPolicyMode::parse(credential.max_policy_mode.as_deref())?;
    if requested <= max {
        return Ok(());
    }

    Err(format!(
        "postgres credential '{}' allows policy mode '{}' but request asked for '{}'",
        credential.id,
        max.as_str(),
        requested.as_str()
    ))
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

    #[test]
    fn postgres_policy_mode_rejects_non_read_only_modes() {
        assert_eq!(
            PostgresPolicyMode::parse(None).unwrap(),
            PostgresPolicyMode::ReadOnly
        );
        assert_eq!(
            PostgresPolicyMode::parse(Some("read-only")).unwrap(),
            PostgresPolicyMode::ReadOnly
        );
        assert!(ensure_provider_supports_policy_mode(
            "postgres/query",
            PostgresPolicyMode::ReadOnly
        )
        .is_ok());
        assert!(
            ensure_provider_supports_policy_mode("postgres/query", PostgresPolicyMode::Write)
                .is_err()
        );
        assert!(
            ensure_provider_supports_policy_mode("postgres/query", PostgresPolicyMode::Admin)
                .is_err()
        );
        assert!(ensure_provider_supports_policy_mode(
            "postgres/export-query",
            PostgresPolicyMode::ReadOnly
        )
        .is_ok());
        assert!(ensure_provider_supports_policy_mode(
            "postgres/export-query",
            PostgresPolicyMode::Write
        )
        .is_err());
        assert!(ensure_provider_supports_policy_mode(
            "postgres/execute",
            PostgresPolicyMode::Write
        )
        .is_ok());
        assert!(requested_policy_mode_for_capability("postgres/execute", None).is_err());
        assert!(
            requested_policy_mode_for_capability("postgres/execute", Some("read-only")).is_err()
        );
        assert!(requested_policy_mode_for_capability("postgres/admin", None).is_err());
        assert!(requested_policy_mode_for_capability("postgres/admin", Some("write")).is_err());
        assert!(
            ensure_provider_supports_policy_mode("postgres/admin", PostgresPolicyMode::Admin)
                .is_ok()
        );
        assert!(ensure_provider_supports_policy_mode(
            "postgres/import-rows",
            PostgresPolicyMode::Write
        )
        .is_ok());
        assert!(requested_policy_mode_for_capability("postgres/import-rows", None).is_err());
        assert!(
            requested_policy_mode_for_capability("postgres/import-rows", Some("read-only"))
                .is_err()
        );
    }

    #[test]
    fn postgres_credential_policy_mode_defaults_to_read_only_and_enforces_ceiling() {
        let mut credential = StoredCredential {
            id: "pg".to_string(),
            provider: PROVIDER.to_string(),
            workspace_id: None,
            group_id: None,
            auth: crate::broker::AuthStrategy::Header {
                header_name: "x-aivault-postgres".to_string(),
                value_template: "{{secret}}".to_string(),
            },
            hosts: vec!["localhost:5432".to_string()],
            secret_ref: "vault:secret:abc".to_string(),
            max_policy_mode: None,
        };

        assert!(
            ensure_credential_allows_policy_mode(&credential, PostgresPolicyMode::ReadOnly).is_ok()
        );
        assert!(
            ensure_credential_allows_policy_mode(&credential, PostgresPolicyMode::Write).is_err()
        );

        credential.max_policy_mode = Some("write".to_string());
        assert!(
            ensure_credential_allows_policy_mode(&credential, PostgresPolicyMode::Write).is_ok()
        );
        assert!(
            ensure_credential_allows_policy_mode(&credential, PostgresPolicyMode::Admin).is_err()
        );
    }

    #[test]
    fn postgres_request_preserves_admin_and_export_options() {
        let envelope = ProxyEnvelope {
            capability: "postgres/admin".to_string(),
            credential: Some("pg".to_string()),
            request: crate::broker::ProxyEnvelopeRequest {
                method: "POST".to_string(),
                path: "/".to_string(),
                headers: Vec::new(),
                body: Some(
                    r#"{"policyMode":"admin","sql":"vacuum public.widgets","format":"csv","maxExportBytes":42}"#
                        .to_string(),
                ),
                multipart: None,
                multipart_files: Vec::new(),
                body_file_path: None,
                url: None,
            },
        };

        let request = parse_request_body(&envelope).unwrap();
        assert_eq!(request.policy_mode.as_deref(), Some("admin"));
        assert_eq!(request.format.as_deref(), Some("csv"));
        assert_eq!(request.max_export_bytes, Some(42));
    }

    #[test]
    fn postgres_file_paths_stay_under_approved_roots() {
        let temp = tempfile::TempDir::new().unwrap();
        let vault = VaultRuntime::new(crate::vault::VaultPaths {
            root_dir: temp.path().to_path_buf(),
        });
        let import_root = vault.paths().root_dir().join("postgres").join("imports");
        std::fs::create_dir_all(&import_root).unwrap();
        std::fs::write(import_root.join("widgets.csv"), "id,name\n1,Ada\n").unwrap();

        let import = approved_postgres_file_path(&vault, "imports", "widgets.csv", false).unwrap();
        assert!(import.starts_with(import_root.canonicalize().unwrap()));
        assert!(approved_postgres_file_path(&vault, "imports", "../secrets.json", false).is_err());
        assert!(approved_postgres_file_path(&vault, "imports", "/tmp/widgets.csv", false).is_err());

        let export = approved_postgres_file_path(&vault, "exports", "widgets.csv", true).unwrap();
        assert!(export.starts_with(
            vault
                .paths()
                .root_dir()
                .join("postgres")
                .join("exports")
                .canonicalize()
                .unwrap()
        ));
        assert!(sanitize_export_filename("my report.csv")
            .unwrap()
            .contains('_'));
        assert!(sanitize_export_filename("../report.csv").is_err());
        assert_eq!(
            ensure_export_extension("report", "jsonl").unwrap(),
            "report.jsonl"
        );
    }
}
