use serde::{Deserialize, Serialize};

use super::crypto::AeadBlob;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretScope {
    Global,
    Workspace {
        workspace_id: String,
    },
    Group {
        workspace_id: String,
        group_id: String,
    },
}

impl SecretScope {
    pub fn to_aad_string(&self) -> String {
        match self {
            SecretScope::Global => "global".to_string(),
            SecretScope::Workspace { workspace_id } => format!("workspace:{}", workspace_id),
            SecretScope::Group {
                workspace_id,
                group_id,
            } => format!("group:{}:{}", workspace_id, group_id),
        }
    }

    pub fn to_display_string(&self) -> String {
        self.to_aad_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedDekRecord {
    pub kek_id: String,
    #[serde(flatten)]
    pub blob: AeadBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretCiphertext {
    pub alg: String,
    pub dek_wrapped: WrappedDekRecord,
    pub value: AeadBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRecord {
    pub secret_id: String,
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub scope: SecretScope,
    /// If true, this secret is owned/managed by the gateway (derived from config or runtime state)
    /// and should not be edited via operator UX.
    #[serde(default)]
    pub system_managed: bool,
    /// If set, this secret may only be used with the pinned provider (derived from compiled-in
    /// registry policy). This is immutable once set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_provider: Option<String>,
    /// AEAD associated data version used for encryption/decryption.
    /// v1: binds to (secret_id, scope)
    /// v2: binds to (secret_id, scope, pinned_provider)
    #[serde(default)]
    pub aad_version: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<i64>,
    #[serde(default)]
    pub value_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<SecretCiphertext>,
    #[serde(default)]
    pub attached_groups: Vec<GroupAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAttachment {
    pub workspace_id: String,
    pub group_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub secret_id: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub scope: SecretScope,
    pub system_managed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_provider: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_used_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub value_version: u64,
    pub attached_groups: Vec<GroupAttachment>,
}

impl From<&SecretRecord> for SecretMeta {
    fn from(r: &SecretRecord) -> Self {
        Self {
            secret_id: r.secret_id.clone(),
            name: r.name.clone(),
            aliases: r.aliases.clone(),
            scope: r.scope.clone(),
            system_managed: r.system_managed,
            pinned_provider: r.pinned_provider.clone(),
            created_at_ms: r.created_at_ms,
            updated_at_ms: r.updated_at_ms,
            last_used_at_ms: r.last_used_at_ms,
            revoked_at_ms: r.revoked_at_ms,
            value_version: r.value_version,
            attached_groups: r.attached_groups.clone(),
        }
    }
}
