use super::credential_id_for_provider_alternative_scope;
use crate::vault::{SecretRef, VaultRuntime};
use serde_json::Value;

/// Resolve only canonical registry aliases, after the broker has selected and
/// authorized the credential. Account discovery must never refresh other accounts.
pub(super) fn prepare_credential(
    vault: &VaultRuntime,
    credential_id: &str,
    rejected_access_token: Option<&str>,
) -> Result<Option<Value>, String> {
    let registry = crate::registry::builtin_registry().map_err(|error| error.to_string())?;
    let Some(provider) = registry.provider("openai") else {
        return Ok(None);
    };
    let alternatives = provider
        .credential_alternatives
        .iter()
        .filter(|alternative| alternative.vault_secrets.contains_key("CODEX_OAUTH_JSON"))
        .collect::<Vec<_>>();
    if !alternatives.iter().any(|alternative| {
        let prefix = format!("{}:{}", provider.provider, alternative.id);
        credential_id == prefix || credential_id.starts_with(&format!("{prefix}:"))
    }) {
        return Ok(None);
    }
    for meta in vault.list_secrets().map_err(|error| error.to_string())? {
        if meta.name != "CODEX_OAUTH_JSON" || meta.revoked_at_ms.is_some() {
            continue;
        }
        if alternatives.iter().any(|alternative| {
            credential_id_for_provider_alternative_scope(
                &provider.provider,
                &alternative.id,
                &meta.scope,
            ) == credential_id
        }) {
            let secret_ref = SecretRef {
                secret_id: meta.secret_id,
            }
            .to_string();
            return crate::codex_oauth::prepare_codex_oauth_value(
                vault,
                &secret_ref,
                rejected_access_token,
            )
            .map(Some);
        }
    }
    Ok(None)
}
