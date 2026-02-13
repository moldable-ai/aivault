use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::vault::VaultRuntime;

mod pinned_secrets_aad_v2;

const APPLIED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppliedMigration {
    id: String,
    applied_at_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppliedMigrationsFile {
    schema_version: u32,
    #[serde(default)]
    applied: Vec<AppliedMigration>,
}

fn migrations_dir(vault: &VaultRuntime) -> PathBuf {
    vault.paths().root_dir().join("migrations")
}

fn applied_path(vault: &VaultRuntime) -> PathBuf {
    migrations_dir(vault).join("applied.json")
}

fn load_applied(vault: &VaultRuntime) -> AppliedMigrationsFile {
    let path = applied_path(vault);
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    let Ok(mut parsed) = serde_json::from_str::<AppliedMigrationsFile>(&raw) else {
        return AppliedMigrationsFile {
            schema_version: APPLIED_SCHEMA_VERSION,
            applied: Vec::new(),
        };
    };
    if parsed.schema_version == 0 {
        parsed.schema_version = APPLIED_SCHEMA_VERSION;
    }
    parsed
}

fn save_applied(vault: &VaultRuntime, file: &AppliedMigrationsFile) -> Result<(), String> {
    let dir = migrations_dir(vault);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_perm = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(&dir, dir_perm);
    }

    let path = applied_path(vault);
    let raw = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    std::fs::write(&path, raw).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_perm = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&path, file_perm);
    }
    Ok(())
}

/// Run best-effort vault migrations on CLI/daemon startup.
///
/// This is intentionally:
/// - no-op when the vault is not initialized
/// - no-op when the vault is locked (migrations will run after unlock)
pub fn run_on_cli_startup(vault: &VaultRuntime) -> Result<(), String> {
    let status = vault.status();
    if !status.enabled || status.locked {
        return Ok(());
    }

    // Load the applied set.
    let mut applied = load_applied(vault);
    let applied_ids: BTreeSet<String> = applied.applied.iter().map(|m| m.id.clone()).collect();

    let mut applied_changed = false;
    applied_changed |= pinned_secrets_aad_v2::run_if_needed(vault, &applied_ids, &mut applied)?;
    if applied_changed {
        applied.schema_version = APPLIED_SCHEMA_VERSION;
        save_applied(vault, &applied)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Intentionally empty: migration coverage lives alongside each migration module.
}
