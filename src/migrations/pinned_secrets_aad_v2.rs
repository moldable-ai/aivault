use std::collections::BTreeSet;

use crate::vault::VaultRuntime;

pub const ID: &str = "2026-02-13-pinned-secrets-aad-v2";

pub(super) fn run_if_needed(
    vault: &VaultRuntime,
    applied_ids: &BTreeSet<String>,
    applied: &mut super::AppliedMigrationsFile,
) -> Result<bool, String> {
    if applied_ids.contains(ID) {
        return Ok(false);
    }

    let outcome = vault
        .migrate_harden_pinned_secrets_aad_v2()
        .map_err(|e| e.to_string())?;
    if outcome.failed != 0 {
        // Fail closed: do not record as applied when there were failures.
        return Ok(false);
    }

    applied.applied.push(super::AppliedMigration {
        id: ID.to_string(),
        applied_at_ms: chrono::Utc::now().timestamp_millis(),
    });

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScopedEnvVar, ENV_LOCK};
    use crate::vault::{SecretRecord, SecretScope, VaultProviderConfig};
    use crate::vault::{VaultPaths, VaultRuntime};
    use base64::Engine;

    #[test]
    fn startup_migrations_harden_legacy_pinned_secrets_aad_v2_and_record_applied() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());

        let key = [7u8; 32];
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::new(VaultPaths {
            root_dir: tmp.path().to_path_buf(),
        });
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-legacy", SecretScope::Global, vec![])
            .unwrap();

        // Simulate a legacy pinned secret: pinnedProvider present but still encrypted with AAD v1.
        let secret_path = vault.paths().secret_path(&meta.secret_id);
        let mut rec: SecretRecord =
            serde_json::from_str(&std::fs::read_to_string(&secret_path).unwrap()).unwrap();
        rec.pinned_provider = Some("openai".to_string());
        rec.aad_version = 1;
        std::fs::write(&secret_path, serde_json::to_string_pretty(&rec).unwrap()).unwrap();

        super::super::run_on_cli_startup(&vault).unwrap();

        let rec2: SecretRecord =
            serde_json::from_str(&std::fs::read_to_string(&secret_path).unwrap()).unwrap();
        assert_eq!(rec2.pinned_provider.as_deref(), Some("openai"));
        assert_eq!(rec2.aad_version, 2);

        let sr = crate::vault::SecretRef {
            secret_id: meta.secret_id,
        }
        .to_string();
        let value = vault
            .resolve_secret_ref(&sr, Some("test.migration"), Some("unit"))
            .unwrap();
        assert_eq!(value, b"sk-legacy".to_vec());

        let applied = super::super::load_applied(&vault);
        assert!(applied.applied.iter().any(|m| m.id == ID));
    }
}
