use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(unix)]
fn chmod_best_effort(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perm).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CapabilityScope {
    Global,
    Workspace {
        workspace_id: String,
    },
    Group {
        workspace_id: String,
        group_id: String,
    },
}

impl CapabilityScope {
    fn normalize(self) -> Result<Self, String> {
        match self {
            Self::Global => Ok(Self::Global),
            Self::Workspace { workspace_id } => {
                let workspace_id = workspace_id.trim();
                if workspace_id.is_empty() {
                    return Err("workspace_id required for workspace scope".to_string());
                }
                Ok(Self::Workspace {
                    workspace_id: workspace_id.to_string(),
                })
            }
            Self::Group {
                workspace_id,
                group_id,
            } => {
                let workspace_id = workspace_id.trim();
                let group_id = group_id.trim();
                if workspace_id.is_empty() || group_id.is_empty() {
                    return Err("workspace_id and group_id required for group scope".to_string());
                }
                Ok(Self::Group {
                    workspace_id: workspace_id.to_string(),
                    group_id: group_id.to_string(),
                })
            }
        }
    }

    fn precedence_for_context(
        &self,
        workspace_id: Option<&str>,
        group_id: Option<&str>,
    ) -> Option<u8> {
        match self {
            Self::Global => Some(1),
            Self::Workspace { workspace_id: ws } => {
                let requested_ws = workspace_id.map(str::trim).unwrap_or_default();
                if requested_ws.is_empty() {
                    None
                } else if ws == requested_ws {
                    Some(2)
                } else {
                    None
                }
            }
            Self::Group {
                workspace_id: ws,
                group_id: bound_group_id,
            } => {
                let requested_ws = workspace_id.map(str::trim).unwrap_or_default();
                let requested_group_id = group_id.map(str::trim).unwrap_or_default();
                if requested_ws.is_empty() || requested_group_id.is_empty() {
                    None
                } else if ws == requested_ws && bound_group_id == requested_group_id {
                    Some(3)
                } else {
                    None
                }
            }
        }
    }

    fn stable_key(&self) -> String {
        match self {
            Self::Global => "global".to_string(),
            Self::Workspace { workspace_id } => format!("workspace:{}", workspace_id),
            Self::Group {
                workspace_id,
                group_id,
            } => format!("group:{}:{}", workspace_id, group_id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityBinding {
    pub capability: String,
    pub secret_ref: String,
    pub scope: CapabilityScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityStoreData {
    version: u32,
    #[serde(default)]
    bindings: Vec<CapabilityBinding>,
}

impl Default for CapabilityStoreData {
    fn default() -> Self {
        Self {
            version: 1,
            bindings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityStore {
    path: PathBuf,
    data: CapabilityStoreData,
}

impl CapabilityStore {
    pub fn open_under(root_dir: &Path) -> Result<Self, String> {
        Self::load(&root_dir.join("capabilities.json"))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self {
                path: path.to_path_buf(),
                data: CapabilityStoreData::default(),
            });
        }

        #[cfg(unix)]
        {
            if let Some(parent) = path.parent() {
                let _ = chmod_best_effort(parent, 0o700);
            }
            let _ = chmod_best_effort(path, 0o600);
        }

        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let data: CapabilityStoreData = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        Ok(Self {
            path: path.to_path_buf(),
            data,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                chmod_best_effort(parent, 0o700)?;
            }
        }
        let raw = serde_json::to_string_pretty(&self.data).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, raw).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            chmod_best_effort(&self.path, 0o600)?;
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<CapabilityBinding> {
        let mut out = self.data.bindings.clone();
        out.sort_by(|a, b| {
            a.capability
                .cmp(&b.capability)
                .then_with(|| a.scope.stable_key().cmp(&b.scope.stable_key()))
                .then_with(|| a.consumer.cmp(&b.consumer))
        });
        out
    }

    pub fn upsert(
        &mut self,
        capability: &str,
        secret_ref: &str,
        scope: CapabilityScope,
        consumer: Option<String>,
    ) -> Result<CapabilityBinding, String> {
        let capability = capability.trim();
        let secret_ref = secret_ref.trim();
        if capability.is_empty() {
            return Err("capability required".to_string());
        }
        if secret_ref.is_empty() {
            return Err("secret_ref required".to_string());
        }

        let scope = scope.normalize()?;
        let consumer = normalize_optional(consumer);
        let key = binding_key(capability, &scope, consumer.as_deref());

        let now = chrono::Utc::now().timestamp_millis();
        let binding = CapabilityBinding {
            capability: capability.to_string(),
            secret_ref: secret_ref.to_string(),
            scope,
            consumer,
            updated_at_ms: now,
        };

        if let Some(idx) = self
            .data
            .bindings
            .iter()
            .position(|b| binding_key(&b.capability, &b.scope, b.consumer.as_deref()) == key)
        {
            self.data.bindings[idx] = binding.clone();
        } else {
            self.data.bindings.push(binding.clone());
        }

        Ok(binding)
    }

    pub fn remove(
        &mut self,
        capability: &str,
        scope: &CapabilityScope,
        consumer: Option<&str>,
    ) -> bool {
        let key = binding_key(capability.trim(), scope, normalize_optional_ref(consumer));
        let before = self.data.bindings.len();
        self.data
            .bindings
            .retain(|b| binding_key(&b.capability, &b.scope, b.consumer.as_deref()) != key);
        self.data.bindings.len() != before
    }

    pub fn resolve(
        &self,
        capability: &str,
        workspace_id: Option<&str>,
        group_id: Option<&str>,
        consumer: Option<&str>,
    ) -> Option<CapabilityBinding> {
        let capability = capability.trim();
        if capability.is_empty() {
            return None;
        }

        let requested_consumer = normalize_optional_ref(consumer);

        self.data
            .bindings
            .iter()
            .filter(|binding| binding.capability == capability)
            .filter_map(|binding| {
                let scope_precedence = binding
                    .scope
                    .precedence_for_context(workspace_id, group_id)?;
                let consumer_precedence = match (requested_consumer, binding.consumer.as_deref()) {
                    (Some(wanted), Some(actual)) if wanted == actual => 2,
                    (Some(_), None) => 1,
                    (None, None) => 1,
                    _ => 0,
                };
                if consumer_precedence == 0 {
                    return None;
                }
                Some((scope_precedence, consumer_precedence, binding))
            })
            .max_by(|a, b| {
                a.0.cmp(&b.0)
                    .then_with(|| a.1.cmp(&b.1))
                    .then_with(|| a.2.updated_at_ms.cmp(&b.2.updated_at_ms))
            })
            .map(|(_, _, binding)| binding.clone())
    }
}

fn binding_key(capability: &str, scope: &CapabilityScope, consumer: Option<&str>) -> String {
    format!(
        "{}|{}|{}",
        capability,
        scope.stable_key(),
        consumer.unwrap_or("")
    )
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn normalize_optional_ref(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_consumer_specific_binding_then_general_binding() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CapabilityStore::open_under(dir.path()).unwrap();

        store
            .upsert(
                "openai/transcription",
                "vault:secret:general",
                CapabilityScope::Global,
                None,
            )
            .unwrap();
        store
            .upsert(
                "openai/transcription",
                "vault:secret:consumer",
                CapabilityScope::Global,
                Some("worker-a".to_string()),
            )
            .unwrap();

        let specific = store
            .resolve("openai/transcription", None, None, Some("worker-a"))
            .unwrap();
        assert_eq!(specific.secret_ref, "vault:secret:consumer");

        let fallback = store
            .resolve("openai/transcription", None, None, Some("worker-b"))
            .unwrap();
        assert_eq!(fallback.secret_ref, "vault:secret:general");
    }

    #[test]
    fn resolve_prefers_group_then_workspace_then_global() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CapabilityStore::open_under(dir.path()).unwrap();

        store
            .upsert(
                "openai/transcription",
                "vault:secret:global",
                CapabilityScope::Global,
                None,
            )
            .unwrap();
        store
            .upsert(
                "openai/transcription",
                "vault:secret:workspace",
                CapabilityScope::Workspace {
                    workspace_id: "default".to_string(),
                },
                None,
            )
            .unwrap();
        store
            .upsert(
                "openai/transcription",
                "vault:secret:group",
                CapabilityScope::Group {
                    workspace_id: "default".to_string(),
                    group_id: "ops".to_string(),
                },
                None,
            )
            .unwrap();

        let group = store
            .resolve("openai/transcription", Some("default"), Some("ops"), None)
            .unwrap();
        assert_eq!(group.secret_ref, "vault:secret:group");

        let workspace = store
            .resolve(
                "openai/transcription",
                Some("default"),
                Some("support"),
                None,
            )
            .unwrap();
        assert_eq!(workspace.secret_ref, "vault:secret:workspace");

        let global = store
            .resolve("openai/transcription", None, None, None)
            .unwrap();
        assert_eq!(global.secret_ref, "vault:secret:global");
    }

    #[test]
    fn remove_deletes_exact_binding_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CapabilityStore::open_under(dir.path()).unwrap();

        store
            .upsert(
                "openai/transcription",
                "vault:secret:a",
                CapabilityScope::Global,
                None,
            )
            .unwrap();
        store
            .upsert(
                "openai/transcription",
                "vault:secret:b",
                CapabilityScope::Global,
                Some("worker-a".to_string()),
            )
            .unwrap();

        let removed = store.remove(
            "openai/transcription",
            &CapabilityScope::Global,
            Some("worker-a"),
        );
        assert!(removed);

        let remaining = store.list();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].secret_ref, "vault:secret:a");
    }

    #[test]
    fn upsert_and_save_roundtrip_preserves_bindings() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CapabilityStore::open_under(dir.path()).unwrap();

        store
            .upsert(
                "openai/transcription",
                "vault:secret:roundtrip",
                CapabilityScope::Workspace {
                    workspace_id: "default".to_string(),
                },
                Some("worker-a".to_string()),
            )
            .unwrap();
        store.save().unwrap();

        let loaded = CapabilityStore::open_under(dir.path()).unwrap();
        let binding = loaded
            .resolve(
                "openai/transcription",
                Some("default"),
                None,
                Some("worker-a"),
            )
            .unwrap();
        assert_eq!(binding.secret_ref, "vault:secret:roundtrip");
    }

    #[test]
    fn resolve_uses_latest_secret_ref_override_for_same_binding_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CapabilityStore::open_under(dir.path()).unwrap();

        store
            .upsert(
                "openai/transcription",
                "vault:secret:old",
                CapabilityScope::Global,
                Some("worker-a".to_string()),
            )
            .unwrap();

        store
            .upsert(
                "openai/transcription",
                "vault:secret:new",
                CapabilityScope::Global,
                Some("worker-a".to_string()),
            )
            .unwrap();

        let resolved = store
            .resolve("openai/transcription", None, None, Some("worker-a"))
            .unwrap();
        assert_eq!(resolved.secret_ref, "vault:secret:new");
    }
}
