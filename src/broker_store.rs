use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::broker::{AuthStrategy, Capability, CapabilityAdvancedPolicy};

#[cfg(unix)]
fn chmod_best_effort(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perm = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perm).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    pub id: String,
    pub provider: String,
    /// Optional execution context this credential is intended for.
    /// If present, invoke paths must supply matching `--workspace-id/--group-id`.
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    pub auth: AuthStrategy,
    pub hosts: Vec<String>,
    pub secret_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoredCapabilityPolicy {
    pub capability_id: String,
    pub policy: CapabilityAdvancedPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrokerStoreData {
    version: u32,
    #[serde(default)]
    credentials: Vec<StoredCredential>,
    #[serde(default)]
    capabilities: Vec<Capability>,
    #[serde(default)]
    policies: Vec<StoredCapabilityPolicy>,
}

impl Default for BrokerStoreData {
    fn default() -> Self {
        Self {
            version: 1,
            credentials: Vec::new(),
            capabilities: Vec::new(),
            policies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrokerStore {
    path: PathBuf,
    data: BrokerStoreData,
}

impl BrokerStore {
    pub fn open_under(root_dir: &Path) -> Result<Self, String> {
        Self::load(&root_dir.join("broker.json"))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self {
                path: path.to_path_buf(),
                data: BrokerStoreData::default(),
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
        let data: BrokerStoreData = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        Ok(Self {
            path: path.to_path_buf(),
            data,
        })
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

    pub fn credentials(&self) -> &[StoredCredential] {
        &self.data.credentials
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.data.capabilities
    }

    pub fn policies(&self) -> &[StoredCapabilityPolicy] {
        &self.data.policies
    }

    pub fn upsert_credential(&mut self, credential: StoredCredential) {
        if let Some(idx) = self
            .data
            .credentials
            .iter()
            .position(|c| c.id == credential.id)
        {
            self.data.credentials[idx] = credential;
        } else {
            self.data.credentials.push(credential);
        }
    }

    pub fn remove_credential(&mut self, id: &str) -> bool {
        let before = self.data.credentials.len();
        self.data.credentials.retain(|c| c.id != id);
        before != self.data.credentials.len()
    }

    pub fn upsert_capability(&mut self, capability: Capability) {
        if let Some(idx) = self
            .data
            .capabilities
            .iter()
            .position(|c| c.id == capability.id)
        {
            self.data.capabilities[idx] = capability;
        } else {
            self.data.capabilities.push(capability);
        }
    }

    pub fn remove_capability(&mut self, id: &str) -> bool {
        let before = self.data.capabilities.len();
        self.data.capabilities.retain(|c| c.id != id);
        before != self.data.capabilities.len()
    }

    pub fn find_capability(&self, id: &str) -> Option<&Capability> {
        self.data
            .capabilities
            .iter()
            .find(|capability| capability.id == id)
    }

    pub fn upsert_policy(&mut self, policy: StoredCapabilityPolicy) {
        if let Some(idx) = self
            .data
            .policies
            .iter()
            .position(|p| p.capability_id == policy.capability_id)
        {
            self.data.policies[idx] = policy;
        } else {
            self.data.policies.push(policy);
        }
    }

    pub fn remove_policy(&mut self, capability_id: &str) -> bool {
        let before = self.data.policies.len();
        self.data
            .policies
            .retain(|policy| policy.capability_id != capability_id);
        before != self.data.policies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_store_roundtrip_and_upsert() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = BrokerStore::open_under(dir.path()).unwrap();

        store.upsert_credential(StoredCredential {
            id: "openai".to_string(),
            provider: "openai".to_string(),
            workspace_id: None,
            group_id: None,
            auth: AuthStrategy::Header {
                header_name: "authorization".to_string(),
                value_template: "Bearer {{secret}}".to_string(),
            },
            hosts: vec!["api.openai.com".to_string()],
            secret_ref: "vault:secret:abc".to_string(),
        });
        store.upsert_capability(Capability {
            id: "openai/chat".to_string(),
            provider: "openai".to_string(),
            allow: crate::broker::AllowPolicy {
                hosts: vec!["api.openai.com".to_string()],
                methods: vec!["POST".to_string()],
                path_prefixes: vec!["/v1/chat".to_string()],
            },
        });
        store.save().unwrap();

        let loaded = BrokerStore::open_under(dir.path()).unwrap();
        assert_eq!(loaded.credentials().len(), 1);
        assert_eq!(loaded.capabilities().len(), 1);
        assert_eq!(loaded.credentials()[0].id, "openai");
        assert_eq!(loaded.capabilities()[0].id, "openai/chat");
    }

    #[test]
    #[cfg(unix)]
    fn broker_store_save_uses_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut store = BrokerStore::open_under(dir.path()).unwrap();
        store.upsert_credential(StoredCredential {
            id: "openai".to_string(),
            provider: "openai".to_string(),
            workspace_id: None,
            group_id: None,
            auth: AuthStrategy::Header {
                header_name: "authorization".to_string(),
                value_template: "Bearer {{secret}}".to_string(),
            },
            hosts: vec!["api.openai.com".to_string()],
            secret_ref: "vault:secret:abc".to_string(),
        });
        store.save().unwrap();

        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let file_mode = std::fs::metadata(dir.path().join("broker.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
    }
}
