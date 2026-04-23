use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Write;
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

pub fn shared_socket_path() -> PathBuf {
    if let Ok(raw) = std::env::var("AIVAULTD_SHARED_SOCKET") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    // Well-known shared socket location for cross-user invocation.
    // This is intentionally stable so agent accounts can auto-discover it.
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Users/Shared/aivault/run/aivaultd.sock")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/run/aivault/aivaultd.sock")
    }
    #[cfg(not(unix))]
    {
        // Non-unix targets don't support unix sockets; keep a deterministic path for callers that
        // compile but should never attempt to use it.
        default_socket_path()
    }
}

#[cfg(unix)]
fn parse_octal_mode(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Accept "660" or "0660".
    u32::from_str_radix(trimmed.trim_start_matches("0o"), 8).ok()
}

#[cfg(unix)]
fn socket_mode_from_env() -> Option<u32> {
    std::env::var("AIVAULTD_SOCKET_MODE")
        .ok()
        .and_then(|v| parse_octal_mode(&v))
}

#[cfg(unix)]
fn socket_dir_mode_from_env() -> Option<u32> {
    std::env::var("AIVAULTD_SOCKET_DIR_MODE")
        .ok()
        .and_then(|v| parse_octal_mode(&v))
}

#[cfg(unix)]
fn is_managed_socket_parent(parent: &Path) -> bool {
    // Canonical per-user run dir:
    // ~/.aivault/run
    if parent == crate::paths::aivault_root_dir().join("run") {
        return true;
    }
    // When AIVAULT_DIR is set, we treat AIVAULT_DIR/run as managed too.
    if let Ok(dir) = std::env::var("AIVAULT_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() && parent == PathBuf::from(trimmed).join("run") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn parse_octal_mode_accepts_common_forms() {
        assert_eq!(parse_octal_mode("600"), Some(0o600));
        assert_eq!(parse_octal_mode("0660"), Some(0o660));
        assert_eq!(parse_octal_mode("0o750"), Some(0o750));
        assert_eq!(parse_octal_mode(""), None);
        assert_eq!(parse_octal_mode("nope"), None);
    }
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
    ExecuteEnvelopeStream {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum DaemonStreamFrame {
    Chunk { body_b64: String },
    Error { error: String },
    End,
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

#[cfg(unix)]
pub fn client_execute_envelope_streaming_typed<W: Write>(
    socket_path: &Path,
    request: DaemonRequest,
    output: &mut W,
) -> Result<(), DaemonClientError> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).map_err(DaemonClientError::Connect)?;

    let raw =
        serde_json::to_vec(&request).map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
    stream
        .write_all(&raw)
        .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
    // Half-close to signal request EOF (daemon reads until end).
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
        if read == 0 {
            return Err(DaemonClientError::Protocol(
                "stream ended before daemon end frame".to_string(),
            ));
        }

        let frame: DaemonStreamFrame = serde_json::from_str(line.trim_end())
            .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
        match frame {
            DaemonStreamFrame::Chunk { body_b64 } => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(body_b64.as_bytes())
                    .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
                output
                    .write_all(&bytes)
                    .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
                output
                    .flush()
                    .map_err(|e| DaemonClientError::Protocol(e.to_string()))?;
            }
            DaemonStreamFrame::Error { error } => return Err(DaemonClientError::Remote(error)),
            DaemonStreamFrame::End => return Ok(()),
        }
    }
}

#[cfg(not(unix))]
pub fn client_execute_envelope_streaming_typed<W: Write>(
    _socket_path: &Path,
    _request: DaemonRequest,
    _output: &mut W,
) -> Result<(), DaemonClientError> {
    Err(DaemonClientError::Protocol(
        "aivaultd requires a unix-like OS (no unix sockets available)".to_string(),
    ))
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
        let parent_existed = parent.exists();
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;

        // Only chmod directories we consider "managed" (our default locations), or ones we just
        // created, or when explicitly configured. Avoid chmod'ing arbitrary existing directories
        // (e.g. /tmp) when users override the socket path.
        let effective_dir_mode = socket_dir_mode_from_env().or_else(|| {
            if is_managed_socket_parent(parent) || !parent_existed {
                Some(0o700)
            } else {
                None
            }
        });
        if let Some(mode) = effective_dir_mode {
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode));
        }
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|e| e.to_string())?;
    }

    let listener = UnixListener::bind(socket_path).map_err(|e| e.to_string())?;
    let socket_mode = socket_mode_from_env().unwrap_or(0o600);
    let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(socket_mode));

    for stream in listener.incoming() {
        let mut stream = stream.map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;

        match serde_json::from_slice::<DaemonRequest>(&buf) {
            Ok(request @ DaemonRequest::ExecuteEnvelopeStream { .. }) => {
                if let Err(err) = handle_stream_request(request, &mut stream) {
                    let _ =
                        write_stream_frame(&mut stream, &DaemonStreamFrame::Error { error: err });
                }
            }
            Ok(request) => {
                let response = handle_request(request);
                let raw = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
                stream.write_all(&raw).map_err(|e| e.to_string())?;
                let _ = stream.flush();
            }
            Err(err) => {
                let response = DaemonResponse::err(format!("invalid request JSON: {}", err));
                let raw = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
                stream.write_all(&raw).map_err(|e| e.to_string())?;
                let _ = stream.flush();
            }
        }

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
            if let Err(err) = crate::migrations::run_on_cli_startup(&vault) {
                return DaemonResponse::err(err);
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
        DaemonRequest::ExecuteEnvelopeStream { .. } => {
            DaemonResponse::err("stream request used non-stream daemon handler".to_string())
        }
    }
}

fn handle_stream_request<W: Write>(request: DaemonRequest, writer: &mut W) -> Result<(), String> {
    let DaemonRequest::ExecuteEnvelopeStream {
        envelope,
        client_ip,
        workspace_id,
        group_id,
    } = request
    else {
        return Err("non-stream request used stream daemon handler".to_string());
    };

    let client_ip = client_ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| "invalid clientIp".to_string())?;

    let vault = crate::vault::VaultRuntime::discover();
    vault.load().map_err(|e| e.to_string())?;
    crate::migrations::run_on_cli_startup(&vault)?;
    let store = crate::broker_store::BrokerStore::open_under(vault.paths().root_dir())?;

    crate::app::run_capability_envelope_streaming(
        &vault,
        &store,
        envelope,
        client_ip,
        workspace_id.as_deref(),
        group_id.as_deref(),
        |chunk| write_stream_chunk(writer, chunk),
    )?;

    write_stream_frame(writer, &DaemonStreamFrame::End)
}

fn write_stream_chunk<W: Write>(writer: &mut W, chunk: &[u8]) -> Result<(), String> {
    write_stream_frame(
        writer,
        &DaemonStreamFrame::Chunk {
            body_b64: base64::engine::general_purpose::STANDARD.encode(chunk),
        },
    )
}

fn write_stream_frame<W: Write>(writer: &mut W, frame: &DaemonStreamFrame) -> Result<(), String> {
    let raw = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    writer.write_all(&raw).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())
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

pub fn client_execute_envelope_streaming<W: Write>(
    socket_path: &Path,
    request: DaemonRequest,
    output: &mut W,
) -> Result<(), String> {
    match client_execute_envelope_streaming_typed(socket_path, request, output) {
        Ok(()) => Ok(()),
        Err(DaemonClientError::Connect(e)) => Err(format!(
            "failed connecting to aivaultd at '{}': {}",
            socket_path.display(),
            e
        )),
        Err(DaemonClientError::Protocol(e)) => Err(format!(
            "invalid streaming response from aivaultd at '{}': {}",
            socket_path.display(),
            e
        )),
        Err(DaemonClientError::Remote(e)) => Err(e),
    }
}
