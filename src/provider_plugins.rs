use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::broker::{AllowPolicy, Capability};
use crate::vault::VaultRuntime;

const MANIFEST_FILE: &str = "provider.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderPluginManifest {
    pub id: String,
    pub version: String,
    pub executable: String,
    pub sha256: String,
    pub enabled: bool,
    pub official: bool,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderPluginStatus {
    pub id: String,
    pub version: String,
    pub official: bool,
    pub installed: bool,
    pub enabled: bool,
    pub install_dir: Option<String>,
    pub executable: Option<String>,
    pub bundled_binary: Option<String>,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone)]
pub struct OfficialProvider {
    pub id: &'static str,
    pub version: &'static str,
    pub binary_name: &'static str,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInvokeRequest {
    pub protocol_version: u32,
    pub capability: String,
    pub secret: Value,
    pub request: Value,
    pub limit: u32,
    pub offset: u64,
    pub timeout_ms: u64,
}

pub fn official_provider(id: &str) -> Option<OfficialProvider> {
    let id = id.trim();
    if id != "postgres" {
        return None;
    }
    Some(OfficialProvider {
        id: "postgres",
        version: "0.1.0",
        binary_name: binary_name("aivault-provider-postgres"),
        capabilities: postgres_capabilities(),
    })
}

pub fn official_providers() -> Vec<OfficialProvider> {
    vec![official_provider("postgres").expect("postgres provider metadata")]
}

pub fn postgres_capability(id: &str) -> Option<Capability> {
    postgres_capabilities()
        .into_iter()
        .find(|capability| capability.id == id.trim())
}

pub fn postgres_capabilities() -> Vec<Capability> {
    [
        "postgres/test-connection",
        "postgres/list-schemas",
        "postgres/list-tables",
        "postgres/describe-table",
        "postgres/preview-table",
        "postgres/query",
    ]
    .into_iter()
    .map(|id| Capability {
        id: id.to_string(),
        provider: "postgres".to_string(),
        allow: AllowPolicy {
            hosts: vec!["*".to_string()],
            methods: vec!["POST".to_string()],
            path_prefixes: vec!["/".to_string()],
        },
    })
    .collect()
}

pub fn provider_root(vault: &VaultRuntime) -> PathBuf {
    vault.paths().root_dir().join("providers")
}

pub fn install_dir(vault: &VaultRuntime, id: &str) -> PathBuf {
    provider_root(vault).join(id)
}

pub fn manifest_path(vault: &VaultRuntime, id: &str) -> PathBuf {
    install_dir(vault, id).join(MANIFEST_FILE)
}

pub fn installed_manifest(
    vault: &VaultRuntime,
    id: &str,
) -> Result<Option<ProviderPluginManifest>, String> {
    let path = manifest_path(vault, id);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("invalid provider manifest '{}': {}", path.display(), e))
}

pub fn list_status(vault: &VaultRuntime) -> Result<Vec<ProviderPluginStatus>, String> {
    let mut statuses = Vec::new();
    for official in official_providers() {
        let installed = installed_manifest(vault, official.id)?;
        let bundled = resolve_bundled_binary(&official, None).ok();
        let (installed_flag, enabled, executable, install_dir) = if let Some(manifest) = installed {
            let dir = install_dir(vault, official.id);
            let exe = executable_path(vault, &manifest)?;
            (
                true,
                manifest.enabled,
                Some(exe.display().to_string()),
                Some(dir.display().to_string()),
            )
        } else {
            (false, false, None, None)
        };
        statuses.push(ProviderPluginStatus {
            id: official.id.to_string(),
            version: official.version.to_string(),
            official: true,
            installed: installed_flag,
            enabled,
            install_dir,
            executable,
            bundled_binary: bundled.map(|p| p.display().to_string()),
            capabilities: official.capabilities,
        });
    }
    Ok(statuses)
}

pub fn install_provider(
    vault: &VaultRuntime,
    id: &str,
    from: Option<&Path>,
    enable: bool,
) -> Result<ProviderPluginManifest, String> {
    let official =
        official_provider(id).ok_or_else(|| format!("unknown official provider '{}'", id))?;
    let source = resolve_bundled_binary(&official, from)?;
    let metadata = fs::metadata(&source).map_err(|e| {
        format!(
            "provider binary '{}' is not readable: {}",
            source.display(),
            e
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "provider binary '{}' is not a file",
            source.display()
        ));
    }

    let dir = install_dir(vault, official.id);
    let bin_dir = dir.join("bin");
    fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
    chmod_dir_best_effort(&provider_root(vault))?;
    chmod_dir_best_effort(&dir)?;
    chmod_dir_best_effort(&bin_dir)?;

    let dest = bin_dir.join(official.binary_name);
    fs::copy(&source, &dest).map_err(|e| {
        format!(
            "failed installing provider binary '{}': {}",
            source.display(),
            e
        )
    })?;
    chmod_exe_best_effort(&dest)?;

    let sha256 = file_sha256(&dest)?;
    let manifest = ProviderPluginManifest {
        id: official.id.to_string(),
        version: official.version.to_string(),
        executable: format!("bin/{}", official.binary_name),
        sha256,
        enabled: enable,
        official: true,
        capabilities: official.capabilities,
    };
    write_manifest(vault, &manifest)?;
    Ok(manifest)
}

pub fn set_enabled(
    vault: &VaultRuntime,
    id: &str,
    enabled: bool,
) -> Result<ProviderPluginManifest, String> {
    let mut manifest = installed_manifest(vault, id)?
        .ok_or_else(|| format!("provider '{}' is not installed", id))?;
    manifest.enabled = enabled;
    verify_manifest(vault, &manifest)?;
    write_manifest(vault, &manifest)?;
    Ok(manifest)
}

pub fn remove_provider(vault: &VaultRuntime, id: &str) -> Result<bool, String> {
    let dir = install_dir(vault, id.trim());
    if !dir.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(true)
}

pub fn invoke_provider(
    vault: &VaultRuntime,
    id: &str,
    request: &ProviderInvokeRequest,
) -> Result<Value, String> {
    let manifest = installed_manifest(vault, id)?.ok_or_else(|| {
        format!(
            "provider '{}' is not installed; run `aivault provider install {}`",
            id, id
        )
    })?;
    if !manifest.enabled {
        return Err(format!(
            "provider '{}' is installed but disabled; run `aivault provider enable {}`",
            id, id
        ));
    }
    let official = verify_manifest(vault, &manifest)?;
    if !official
        .capabilities
        .iter()
        .any(|capability| capability.id == request.capability)
    {
        return Err(format!(
            "provider '{}' does not declare capability '{}'",
            id, request.capability
        ));
    }

    let exe = executable_path(vault, &manifest)?;
    let mut child = Command::new(&exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start provider '{}': {}", exe.display(), e))?;

    let input = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&input).map_err(|e| e.to_string())?;
    }
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("provider '{}' failed with {}", id, output.status)
        } else {
            stderr
        });
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("provider '{}' returned invalid JSON: {}", id, e))
}

fn write_manifest(vault: &VaultRuntime, manifest: &ProviderPluginManifest) -> Result<(), String> {
    let dir = install_dir(vault, &manifest.id);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let raw = serde_json::to_string_pretty(manifest).map_err(|e| e.to_string())?;
    fs::write(dir.join(MANIFEST_FILE), raw).map_err(|e| e.to_string())?;
    chmod_file_best_effort(&dir.join(MANIFEST_FILE))?;
    Ok(())
}

fn verify_manifest(
    vault: &VaultRuntime,
    manifest: &ProviderPluginManifest,
) -> Result<OfficialProvider, String> {
    let official = official_provider(&manifest.id)
        .ok_or_else(|| format!("provider '{}' is not an official provider", manifest.id))?;
    if !manifest.official {
        return Err(format!(
            "provider '{}' is not an official provider",
            manifest.id
        ));
    }
    if manifest.version != official.version {
        return Err(format!(
            "provider '{}' version '{}' does not match official version '{}'",
            manifest.id, manifest.version, official.version
        ));
    }
    if manifest.capabilities != official.capabilities {
        return Err(format!(
            "provider '{}' capabilities do not match official metadata",
            manifest.id
        ));
    }
    let exe = executable_path(vault, manifest)?;
    let actual = file_sha256(&exe)?;
    if actual != manifest.sha256 {
        return Err(format!(
            "provider '{}' binary digest mismatch; reinstall provider before use",
            manifest.id
        ));
    }
    Ok(official)
}

fn executable_path(
    vault: &VaultRuntime,
    manifest: &ProviderPluginManifest,
) -> Result<PathBuf, String> {
    let relative = Path::new(&manifest.executable);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "provider '{}' manifest executable must stay inside provider dir",
            manifest.id
        ));
    }
    Ok(install_dir(vault, &manifest.id).join(relative))
}

fn resolve_bundled_binary(
    official: &OfficialProvider,
    explicit: Option<&Path>,
) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }

    let env_name = format!(
        "AIVAULT_PROVIDER_{}_BIN",
        official.id.to_ascii_uppercase().replace('-', "_")
    );
    if let Ok(path) = std::env::var(&env_name) {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }

    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            candidates.push(
                dir.join("providers")
                    .join(official.id)
                    .join(official.binary_name),
            );
            candidates.push(dir.join(official.binary_name));
            if let Some(parent) = dir.parent() {
                candidates.push(
                    parent
                        .join("providers")
                        .join(official.id)
                        .join(official.binary_name),
                );
            }
        }
    }
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidates.push(
        repo_root
            .join("providers")
            .join(official.id)
            .join("target")
            .join("debug")
            .join(official.binary_name),
    );
    candidates.push(
        repo_root
            .join("providers")
            .join(official.id)
            .join("target")
            .join("release")
            .join(official.binary_name),
    );

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "bundled binary for provider '{}' was not found; build it with `pnpm provider:build:{}` or pass --from <path>",
        official.id, official.id
    ))
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("failed reading '{}': {}", path.display(), e))?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

fn binary_name(base: &'static str) -> &'static str {
    #[cfg(windows)]
    {
        match base {
            "aivault-provider-postgres" => "aivault-provider-postgres.exe",
            _ => base,
        }
    }
    #[cfg(not(windows))]
    {
        base
    }
}

#[cfg(unix)]
fn chmod_dir_best_effort(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn chmod_dir_best_effort(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn chmod_file_best_effort(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn chmod_file_best_effort(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn chmod_exe_best_effort(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn chmod_exe_best_effort(_path: &Path) -> Result<(), String> {
    Ok(())
}
