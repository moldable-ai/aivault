use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::broker::ProxyEnvelope;

pub fn default_socket_path() -> PathBuf {
    // In tests and dev, `AIVAULT_DIR` is often set to a temp vault root. When it is, prefer
    // keeping the daemon socket under that root so parallel test runs do not contend on
    // ~/.aivault/run.
    if let Ok(dir) = std::env::var("AIVAULT_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join("run").join("aivaultd.sock");
        }
    }

    crate::paths::aivault_root_dir()
        .join("run")
        .join("aivaultd.sock")
}

pub fn socket_path_from_env() -> Option<PathBuf> {
    if let Ok(raw) = std::env::var("AIVAULTD_SOCKET") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DaemonRequest {
    ExecuteEnvelope {
        envelope: ProxyEnvelope,
        client_ip: String,
        #[serde(default)]
        workspace_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DaemonResponse {
    fn ok(value: Value) -> Self {
        Self {
            ok: true,
            value: Some(value),
            error: None,
        }
    }

    fn err(message: String) -> Self {
        Self {
            ok: false,
            value: None,
            error: Some(message),
        }
    }
}

#[derive(Debug)]
pub enum DaemonClientError {
    Connect(std::io::Error),
    Protocol(String),
    Remote(String),
}

#[cfg(unix)]
pub fn client_execute_envelope_typed(
    socket_path: &Path,
    request: DaemonRequest,
) -> Result<Value, DaemonClientError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).map_err(DaemonClientError::Connect)?;

    let raw =
        serde_json::to_vec(&request).map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
    stream
        .write_all(&raw)
        .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
    // Half-close to signal request EOF (daemon reads until end).
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
    let response: DaemonResponse =
        serde_json::from_slice(&buf).map_err(|e| DaemonClientError::Protocol(e.to_string()))?;

    if response.ok {
        response.value.ok_or_else(|| {
            DaemonClientError::Protocol("missing value in aivaultd response".to_string())
        })
    } else {
        Err(DaemonClientError::Remote(
            response
                .error
                .unwrap_or_else(|| "unknown aivaultd error".to_string()),
        ))
    }
}

#[cfg(not(unix))]
pub fn client_execute_envelope_typed(
    _socket_path: &Path,
    _request: DaemonRequest,
) -> Result<Value, DaemonClientError> {
    Err(DaemonClientError::Protocol(
        "aivaultd requires a unix-like OS (no unix sockets available)".to_string(),
    ))
}

#[cfg(unix)]
pub fn serve(socket_path: &Path, once: bool) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|e| e.to_string())?;
    }

    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));

    for stream in listener.incoming() {
        let mut stream = stream.map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;

        let response = match serde_json::from_slice::<DaemonRequest>(&buf) {
            Ok(request) => handle_request(request),
            Err(err) => DaemonResponse::err(format!("invalid request JSON: {}", err)),
        };

        let raw = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
        stream.write_all(&raw).map_err(|e| e.to_string())?;
        let _ = stream.flush();

        if once {
            break;
        }
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn serve(_socket_path: &Path, _once: bool) -> Result<(), String> {
    Err("aivaultd requires a unix-like OS (no unix sockets available)".to_string())
}

fn handle_request(request: DaemonRequest) -> DaemonResponse {
    match request {
        DaemonRequest::ExecuteEnvelope {
            envelope,
            client_ip,
            workspace_id,
            group_id,
        } => {
            let client_ip = match client_ip.parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(_) => return DaemonResponse::err("invalid clientIp".to_string()),
            };

            let vault = crate::vault::VaultRuntime::discover();
            if let Err(err) = vault.load() {
                return DaemonResponse::err(err.to_string());
            }
            let store = match crate::broker_store::BrokerStore::open_under(vault.paths().root_dir())
            {
                Ok(store) => store,
                Err(err) => return DaemonResponse::err(err),
            };

            match crate::app::run_capability_envelope(
                &vault,
                &store,
                envelope,
                client_ip,
                workspace_id.as_deref(),
                group_id.as_deref(),
            ) {
                Ok(value) => DaemonResponse::ok(value),
                Err(err) => DaemonResponse::err(err),
            }
        }
    }
}

pub fn client_execute_envelope(
    socket_path: &Path,
    request: DaemonRequest,
) -> Result<Value, String> {
    match client_execute_envelope_typed(socket_path, request) {
        Ok(v) => Ok(v),
        Err(DaemonClientError::Connect(e)) => Err(format!(
            "failed connecting to aivaultd at '{}': {}",
            socket_path.display(),
            e
        )),
        Err(DaemonClientError::Protocol(e)) => Err(format!(
            "invalid response from aivaultd at '{}': {}",
            socket_path.display(),
            e
        )),
        Err(DaemonClientError::Remote(e)) => Err(e),
    }
}
