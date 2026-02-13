mod audit;
mod crypto;
mod paths;
mod refs;
mod store;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::vault::crypto::{
    aead_decrypt_xchacha20poly1305, aead_encrypt_xchacha20poly1305, derive_kek_from_passphrase,
    random_key_32, sha256_hex, AeadBlob, PassphraseKdfConfig,
};

pub use audit::{append_audit_event, read_audit_events, read_audit_events_before, VaultAuditEvent};
pub use paths::VaultPaths;
pub use refs::SecretRef;
pub use store::{SecretMeta, SecretRecord, SecretScope, TeamAttachment};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultProviderType {
    MacosKeychain,
    Passphrase,
    Env,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VaultProviderConfig {
    MacosKeychain {
        service: String,
        account: String,
    },
    Passphrase {
        kdf: PassphraseKdfConfig,
        check: VaultCheckRecord,
    },
    Env {
        env_var: String,
    },
    File {
        path: String,
    },
}

impl VaultProviderConfig {
    pub fn provider_type(&self) -> VaultProviderType {
        match self {
            VaultProviderConfig::MacosKeychain { .. } => VaultProviderType::MacosKeychain,
            VaultProviderConfig::Passphrase { .. } => VaultProviderType::Passphrase,
            VaultProviderConfig::Env { .. } => VaultProviderType::Env,
            VaultProviderConfig::File { .. } => VaultProviderType::File,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultCheckRecord {
    pub sha256_hex: String,
    pub blob: AeadBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    pub version: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub provider: VaultProviderConfig,
    /// Best-effort identifier for the current KEK (sha256 of key bytes).
    pub kek_id: String,
}

impl VaultConfig {
    pub fn kek_id_for_key(key_32: &[u8; 32]) -> String {
        sha256_hex(key_32)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub enabled: bool,
    pub provider_type: Option<VaultProviderType>,
    pub locked: bool,
    pub kek_id: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("vault not enabled")]
    NotEnabled,
    #[error("vault locked")]
    Locked,
    #[error("vault provider misconfigured: {0}")]
    Provider(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Clone)]
pub struct VaultRuntime {
    paths: VaultPaths,
    cfg: Arc<Mutex<Option<VaultConfig>>>,
    // For passphrase provider only: derived KEK (cleared on lock).
    unlocked_kek: Arc<Mutex<Option<[u8; 32]>>>,
    audit_enabled: Arc<AtomicBool>,
}

struct VaultInitLock {
    path: std::path::PathBuf,
}

impl Drop for VaultInitLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl VaultRuntime {
    pub fn discover() -> Self {
        Self::new(VaultPaths::discover())
    }

    pub fn new(paths: VaultPaths) -> Self {
        Self {
            paths,
            cfg: Arc::new(Mutex::new(None)),
            unlocked_kek: Arc::new(Mutex::new(None)),
            audit_enabled: Arc::new(AtomicBool::new(!vault_disk_logs_disabled())),
        }
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    pub fn set_audit_enabled(&self, enabled: bool) {
        self.audit_enabled.store(enabled, Ordering::Relaxed);
    }

    fn maybe_audit(&self, event: VaultAuditEvent) {
        if !self.audit_enabled.load(Ordering::Relaxed) {
            return;
        }
        let _ = append_audit_event(&self.paths.audit_dir(), &event);
    }

    fn acquire_init_lock(&self) -> Result<Option<VaultInitLock>, VaultError> {
        // If already initialized, no lock needed.
        if self.paths.config_path().exists() {
            return Ok(None);
        }

        // Ensure the root dir exists so the lock can be created.
        std::fs::create_dir_all(self.paths.root_dir()).ok();

        let lock_path = self.paths.root_dir().join(".init-lock");
        let start = std::time::Instant::now();

        loop {
            match std::fs::create_dir(&lock_path) {
                Ok(()) => {
                    // Write a small marker for debugging/stale detection. Best-effort.
                    let _ = std::fs::write(
                        lock_path.join("info.txt"),
                        format!(
                            "pid={}\nts_ms={}\n",
                            std::process::id(),
                            chrono::Utc::now().timestamp_millis()
                        ),
                    );
                    return Ok(Some(VaultInitLock { path: lock_path }));
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Someone else is initializing. If config appears, proceed without locking.
                    if self.paths.config_path().exists() {
                        return Ok(None);
                    }

                    // If the lock looks stale, try to clear it.
                    let stale = std::fs::metadata(&lock_path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .map(|age| age > Duration::from_secs(30))
                        .unwrap_or(false);
                    if stale {
                        let _ = std::fs::remove_dir_all(&lock_path);
                    } else {
                        std::thread::sleep(Duration::from_millis(25));
                    }

                    if start.elapsed() > Duration::from_secs(3) {
                        // Last chance: if config exists now, load it; otherwise fail loudly.
                        if self.paths.config_path().exists() {
                            return Ok(None);
                        }
                        return Err(VaultError::Other(
                            "vault init lock held too long".to_string(),
                        ));
                    }
                }
                Err(err) => return Err(VaultError::Io(err)),
            }
        }
    }

    pub fn load(&self) -> Result<(), VaultError> {
        let path = self.paths.config_path();
        if !path.exists() {
            *self.cfg.lock().unwrap() = None;
            *self.unlocked_kek.lock().unwrap() = None;
            // Vault is mandatory: auto-initialize with a safe default provider.
            self.ensure_default_initialized()?;
            return Ok(());
        }
        let raw = std::fs::read_to_string(&path)?;
        let mut cfg: VaultConfig = serde_json::from_str(&raw)?;

        // Self-heal: if Keychain provider is configured but the keychain entry is missing,
        // recreate it only when there are no secrets (otherwise we'd make them unrecoverable).
        if let VaultProviderConfig::MacosKeychain { service, account } = &cfg.provider {
            let missing = keychain_entry_missing(service, account)?;
            if missing {
                let secrets_dir = self.paths.secrets_dir();
                let has_secrets = secrets_dir.exists()
                    && std::fs::read_dir(&secrets_dir)
                        .ok()
                        .map(|mut it| it.any(|e| e.ok().is_some_and(|e| e.path().is_file())))
                        .unwrap_or(false);
                if has_secrets {
                    return Err(VaultError::Provider(format!(
                        "Keychain entry missing for service={}, account={} (secrets exist; refusing to overwrite).",
                        service, account
                    )));
                }

                let kek = random_key_32();
                store_kek_keychain(service, account, &kek)?;
                // Verify we can immediately read the key back (some environments are misconfigured).
                let loaded = load_kek_keychain(service, account).map_err(VaultError::Provider)?;
                if loaded != kek {
                    return Err(VaultError::Provider(
                        "keychain verification failed".to_string(),
                    ));
                }
                cfg.kek_id = VaultConfig::kek_id_for_key(&kek);
                cfg.updated_at_ms = chrono::Utc::now().timestamp_millis();
                self.write_config(&cfg)?;
                self.maybe_audit(VaultAuditEvent {
                    ts_ms: chrono::Utc::now().timestamp_millis(),
                    kind: "vault.repair_keychain".to_string(),
                    secret_id: None,
                    scope: None,
                    actor: Some("operator".to_string()),
                    capability: None,
                    consumer: None,
                    note: Some(format!("service={},account={}", service, account)),
                });
            }
        }

        *self.cfg.lock().unwrap() = Some(cfg);
        // Passphrase provider remains locked until explicitly unlocked.
        *self.unlocked_kek.lock().unwrap() = None;
        Ok(())
    }

    pub fn status(&self) -> VaultStatus {
        let cfg = self.cfg.lock().unwrap().clone();
        let enabled = cfg.is_some();
        let provider_type = cfg.as_ref().map(|c| c.provider.provider_type());
        let locked = match cfg.as_ref().map(|c| c.provider.provider_type()) {
            Some(VaultProviderType::Passphrase) => self.unlocked_kek.lock().unwrap().is_none(),
            Some(_) => false,
            None => true,
        };
        VaultStatus {
            enabled,
            provider_type,
            locked,
            kek_id: cfg.map(|c| c.kek_id),
        }
    }

    pub fn init(&self, provider: VaultProviderConfig) -> Result<VaultStatus, VaultError> {
        let _lock = self.acquire_init_lock()?;
        if self.paths.config_path().exists() {
            self.load()?;
            return Ok(self.status());
        }
        self.init_unlocked(provider)
    }

    fn init_unlocked(&self, provider: VaultProviderConfig) -> Result<VaultStatus, VaultError> {
        self.paths.ensure_dirs()?;

        // Initialize provider and produce a KEK.
        let (kek, provider) = match provider {
            VaultProviderConfig::MacosKeychain { service, account } => {
                let kek = random_key_32();
                store_kek_keychain(&service, &account, &kek)?;
                // Verify the key is immediately retrievable; some environments don't have
                // functional secure storage (tests/CI/headless).
                let loaded = load_kek_keychain(&service, &account).map_err(VaultError::Provider)?;
                if loaded != kek {
                    return Err(VaultError::Provider(
                        "keychain verification failed".to_string(),
                    ));
                }
                (kek, VaultProviderConfig::MacosKeychain { service, account })
            }
            VaultProviderConfig::Env { env_var } => {
                // For env provider, require the key to already be present, otherwise the gateway
                // cannot ever decrypt unattended.
                let kek = load_kek_from_env(&env_var).map_err(VaultError::Provider)?;
                (kek, VaultProviderConfig::Env { env_var })
            }
            VaultProviderConfig::File { path } => {
                match load_kek_from_file(&path) {
                    Ok(kek) => (kek, VaultProviderConfig::File { path }),
                    Err(_err) => {
                        // If the file does not exist yet, generate and store a key to support
                        // seamless local operation and first-run UX.
                        let kek = random_key_32();
                        store_kek_file(&path, &kek).map_err(VaultError::Provider)?;
                        (kek, VaultProviderConfig::File { path })
                    }
                }
            }
            VaultProviderConfig::Passphrase { kdf: _, .. } => {
                return Err(VaultError::Other(
                    "passphrase init must be done via init_passphrase".to_string(),
                ));
            }
        };

        let now = chrono::Utc::now().timestamp_millis();
        let cfg = VaultConfig {
            version: 1,
            created_at_ms: now,
            updated_at_ms: now,
            provider,
            kek_id: VaultConfig::kek_id_for_key(&kek),
        };
        self.write_config(&cfg)?;
        *self.cfg.lock().unwrap() = Some(cfg);
        *self.unlocked_kek.lock().unwrap() = Some(kek);
        self.maybe_audit(VaultAuditEvent {
            ts_ms: now,
            kind: "vault.init".to_string(),
            secret_id: None,
            scope: None,
            actor: Some("operator".to_string()),
            capability: None,
            consumer: None,
            note: None,
        });
        Ok(self.status())
    }

    pub fn init_passphrase(&self, passphrase: &str) -> Result<VaultStatus, VaultError> {
        let _lock = self.acquire_init_lock()?;
        if self.paths.config_path().exists() {
            self.load()?;
            return Ok(self.status());
        }
        self.init_passphrase_unlocked(passphrase)
    }

    fn init_passphrase_unlocked(&self, passphrase: &str) -> Result<VaultStatus, VaultError> {
        self.paths.ensure_dirs()?;
        let kdf = PassphraseKdfConfig::new_random_default();
        let kek = derive_kek_from_passphrase(passphrase, &kdf).map_err(VaultError::Provider)?;

        // Create a check record to validate future unlock attempts without secrets.
        let check_plain = random_key_32();
        let check_sha = sha256_hex(&check_plain);
        let aad = b"vault:check:v1";
        let blob = aead_encrypt_xchacha20poly1305(&kek, &check_plain, aad)
            .map_err(VaultError::Provider)?;
        let check = VaultCheckRecord {
            sha256_hex: check_sha,
            blob,
        };

        let now = chrono::Utc::now().timestamp_millis();
        let cfg = VaultConfig {
            version: 1,
            created_at_ms: now,
            updated_at_ms: now,
            provider: VaultProviderConfig::Passphrase { kdf, check },
            kek_id: VaultConfig::kek_id_for_key(&kek),
        };
        self.write_config(&cfg)?;
        *self.cfg.lock().unwrap() = Some(cfg);
        *self.unlocked_kek.lock().unwrap() = Some(kek);
        self.maybe_audit(VaultAuditEvent {
            ts_ms: now,
            kind: "vault.init".to_string(),
            secret_id: None,
            scope: None,
            actor: Some("operator".to_string()),
            capability: None,
            consumer: None,
            note: Some("passphrase".to_string()),
        });
        Ok(self.status())
    }

    pub fn unlock(&self, passphrase: &str) -> Result<VaultStatus, VaultError> {
        let cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let VaultProviderConfig::Passphrase { kdf, check } = cfg.provider else {
            return Ok(self.status());
        };
        let kek = derive_kek_from_passphrase(passphrase, &kdf).map_err(VaultError::Provider)?;
        let aad = b"vault:check:v1";
        let plain =
            aead_decrypt_xchacha20poly1305(&kek, &check.blob, aad).map_err(VaultError::Provider)?;
        if sha256_hex(&plain) != check.sha256_hex {
            return Err(VaultError::Provider("invalid passphrase".to_string()));
        }
        *self.unlocked_kek.lock().unwrap() = Some(kek);
        self.maybe_audit(VaultAuditEvent {
            ts_ms: chrono::Utc::now().timestamp_millis(),
            kind: "vault.unlock".to_string(),
            secret_id: None,
            scope: None,
            actor: Some("operator".to_string()),
            capability: None,
            consumer: None,
            note: None,
        });
        Ok(self.status())
    }

    pub fn lock(&self) -> Result<VaultStatus, VaultError> {
        {
            let mut guard = self.unlocked_kek.lock().unwrap();
            if let Some(mut kek) = guard.take() {
                kek.zeroize();
            }
        }
        self.maybe_audit(VaultAuditEvent {
            ts_ms: chrono::Utc::now().timestamp_millis(),
            kind: "vault.lock".to_string(),
            secret_id: None,
            scope: None,
            actor: Some("operator".to_string()),
            capability: None,
            consumer: None,
            note: None,
        });
        Ok(self.status())
    }

    pub fn rotate_master_key(
        &self,
        new_key: Option<&str>,
        new_passphrase: Option<&str>,
    ) -> Result<VaultStatus, VaultError> {
        let mut cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;

        let old_kek = self.get_kek(&cfg)?;

        // Switching to passphrase mode is allowed from any provider. This is the "high security"
        // mode (manual unlock after restart).
        let (new_kek, new_provider, should_unlock) = if let Some(pw) = new_passphrase {
            let kdf = PassphraseKdfConfig::new_random_default();
            let new_kek = derive_kek_from_passphrase(pw, &kdf).map_err(VaultError::Provider)?;
            let check_plain = random_key_32();
            let check_sha = sha256_hex(&check_plain);
            let aad = b"vault:check:v1";
            let blob = aead_encrypt_xchacha20poly1305(&new_kek, &check_plain, aad)
                .map_err(VaultError::Provider)?;
            let check = VaultCheckRecord {
                sha256_hex: check_sha,
                blob,
            };
            (
                new_kek,
                VaultProviderConfig::Passphrase { kdf, check },
                true,
            )
        } else {
            match &cfg.provider {
                VaultProviderConfig::MacosKeychain { service, account } => {
                    // Keep previous key available by writing a new account and switching config.
                    let ts = chrono::Utc::now().timestamp_millis();
                    let new_account = format!("{}-{}", account, ts);
                    let new_kek = random_key_32();
                    store_kek_keychain(service, &new_account, &new_kek)?;
                    (
                        new_kek,
                        VaultProviderConfig::MacosKeychain {
                            service: service.clone(),
                            account: new_account,
                        },
                        true,
                    )
                }
                VaultProviderConfig::Env { .. } | VaultProviderConfig::File { .. } => {
                    let Some(new_key) = new_key else {
                        return Err(VaultError::Other(
                            "new_key required for env/file provider rotation".to_string(),
                        ));
                    };
                    let new_kek = parse_key_32(new_key).map_err(VaultError::Provider)?;
                    (new_kek, cfg.provider.clone(), true)
                }
                VaultProviderConfig::Passphrase { .. } => {
                    return Err(VaultError::Other(
                        "new_passphrase required for passphrase rotation".to_string(),
                    ));
                }
            }
        };

        // Rewrap DEKs for all secrets with the new KEK.
        let new_kek_id = VaultConfig::kek_id_for_key(&new_kek);
        self.rewrap_all_secrets(&old_kek, &new_kek, &new_kek_id)?;

        cfg.provider = new_provider;
        cfg.kek_id = new_kek_id;
        cfg.updated_at_ms = chrono::Utc::now().timestamp_millis();
        self.write_config(&cfg)?;
        *self.cfg.lock().unwrap() = Some(cfg);

        if should_unlock {
            *self.unlocked_kek.lock().unwrap() = Some(new_kek);
        }

        self.maybe_audit(VaultAuditEvent {
            ts_ms: chrono::Utc::now().timestamp_millis(),
            kind: "vault.rotate_master_key".to_string(),
            secret_id: None,
            scope: None,
            actor: Some("operator".to_string()),
            capability: None,
            consumer: None,
            note: None,
        });

        Ok(self.status())
    }

    pub fn create_secret(
        &self,
        name: &str,
        value: &[u8],
        scope: SecretScope,
        aliases: Vec<String>,
    ) -> Result<SecretMeta, VaultError> {
        self.create_secret_with_management(name, value, scope, aliases, false)
    }

    pub fn create_system_secret(
        &self,
        name: &str,
        value: &[u8],
        scope: SecretScope,
        aliases: Vec<String>,
    ) -> Result<SecretMeta, VaultError> {
        self.create_secret_with_management(name, value, scope, aliases, true)
    }

    fn create_secret_with_management(
        &self,
        name: &str,
        value: &[u8],
        scope: SecretScope,
        aliases: Vec<String>,
        system_managed: bool,
    ) -> Result<SecretMeta, VaultError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::Other("secret name required".to_string()));
        }

        let cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let kek = self.get_kek(&cfg)?;
        let aliases = normalize_aliases(aliases);
        self.ensure_name_alias_unique_for_scope(&scope, name, &aliases, None)?;

        let now = chrono::Utc::now().timestamp_millis();
        let secret_id = Uuid::new_v4().to_string();
        let dek = random_key_32();
        let kek_id = cfg.kek_id.clone();

        let aad_value = format!("vault:secret:v1:{}:{}", secret_id, scope.to_aad_string());
        let aad_value = aad_value.as_bytes();
        let wrapped_dek =
            aead_encrypt_xchacha20poly1305(&kek, &dek, aad_value).map_err(VaultError::Provider)?;

        let value_blob =
            aead_encrypt_xchacha20poly1305(&dek, value, aad_value).map_err(VaultError::Provider)?;

        let record = SecretRecord {
            secret_id: secret_id.clone(),
            name: name.to_string(),
            aliases,
            scope: scope.clone(),
            system_managed,
            created_at_ms: now,
            updated_at_ms: now,
            last_used_at_ms: None,
            revoked_at_ms: None,
            value_version: 1,
            ciphertext: Some(store::SecretCiphertext {
                alg: "xchacha20poly1305+envelope".to_string(),
                dek_wrapped: store::WrappedDekRecord {
                    kek_id,
                    blob: wrapped_dek,
                },
                value: value_blob,
            }),
            attached_teams: Vec::new(),
        };
        self.write_secret(&record)?;
        self.audit_secret_event("secret.create", Some(&record), None);
        Ok(SecretMeta::from(&record))
    }

    pub fn get_secret_meta(&self, secret_id: &str) -> Result<SecretMeta, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let rec = self.read_secret(secret_id)?;
        Ok(SecretMeta::from(&rec))
    }

    pub fn set_secret_system_managed(
        &self,
        secret_id: &str,
        system_managed: bool,
    ) -> Result<SecretMeta, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let mut rec = self.read_secret(secret_id)?;
        if rec.system_managed == system_managed {
            return Ok(SecretMeta::from(&rec));
        }
        rec.system_managed = system_managed;
        rec.updated_at_ms = chrono::Utc::now().timestamp_millis();
        self.write_secret(&rec)?;
        self.audit_secret_event("secret.system_managed", Some(&rec), None);
        Ok(SecretMeta::from(&rec))
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretMeta>, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let dir = self.paths.secrets_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap_or_default();
            if let Ok(rec) = serde_json::from_str::<SecretRecord>(&raw) {
                out.push(SecretMeta::from(&rec));
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn update_secret_meta(
        &self,
        secret_id: &str,
        name: Option<String>,
        aliases: Option<Vec<String>>,
    ) -> Result<SecretMeta, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let mut rec = self.read_secret(secret_id)?;
        if let Some(name) = name {
            let n = name.trim().to_string();
            if n.is_empty() {
                return Err(VaultError::Other("secret name required".to_string()));
            }
            rec.name = n;
        }
        if let Some(aliases) = aliases {
            rec.aliases = normalize_aliases(aliases);
        }
        self.ensure_name_alias_unique_for_scope(
            &rec.scope,
            &rec.name,
            &rec.aliases,
            Some(secret_id),
        )?;
        rec.updated_at_ms = chrono::Utc::now().timestamp_millis();
        self.write_secret(&rec)?;
        self.audit_secret_event("secret.update", Some(&rec), None);
        Ok(SecretMeta::from(&rec))
    }

    pub fn rotate_secret_value(
        &self,
        secret_id: &str,
        value: &[u8],
    ) -> Result<SecretMeta, VaultError> {
        let cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let kek = self.get_kek(&cfg)?;

        let mut rec = self.read_secret(secret_id)?;
        if rec.revoked_at_ms.is_some() {
            return Err(VaultError::Other("secret revoked".to_string()));
        }
        let scope = rec.scope.clone();
        let dek = random_key_32();
        let kek_id = cfg.kek_id.clone();
        let aad_value = format!("vault:secret:v1:{}:{}", secret_id, scope.to_aad_string());
        let aad_value = aad_value.as_bytes();
        let wrapped_dek =
            aead_encrypt_xchacha20poly1305(&kek, &dek, aad_value).map_err(VaultError::Provider)?;
        let value_blob =
            aead_encrypt_xchacha20poly1305(&dek, value, aad_value).map_err(VaultError::Provider)?;
        rec.ciphertext = Some(store::SecretCiphertext {
            alg: "xchacha20poly1305+envelope".to_string(),
            dek_wrapped: store::WrappedDekRecord {
                kek_id,
                blob: wrapped_dek,
            },
            value: value_blob,
        });
        rec.value_version = rec.value_version.saturating_add(1).max(2);
        rec.updated_at_ms = chrono::Utc::now().timestamp_millis();
        self.write_secret(&rec)?;
        self.audit_secret_event("secret.rotate", Some(&rec), None);
        Ok(SecretMeta::from(&rec))
    }

    pub fn revoke_secret(&self, secret_id: &str) -> Result<SecretMeta, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let mut rec = self.read_secret(secret_id)?;
        rec.revoked_at_ms = Some(chrono::Utc::now().timestamp_millis());
        rec.ciphertext = None;
        rec.updated_at_ms = chrono::Utc::now().timestamp_millis();
        self.write_secret(&rec)?;
        self.audit_secret_event("secret.revoke", Some(&rec), None);
        Ok(SecretMeta::from(&rec))
    }

    pub fn attach_secret_to_team(
        &self,
        secret_id: &str,
        workspace_id: &str,
        team: &str,
    ) -> Result<SecretMeta, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let mut rec = self.read_secret(secret_id)?;
        let ws = workspace_id.trim();
        let team = team.trim();
        if ws.is_empty() || team.is_empty() {
            return Err(VaultError::Other("workspace and team required".to_string()));
        }
        if !rec
            .attached_teams
            .iter()
            .any(|t| t.workspace_id == ws && t.team == team)
        {
            rec.attached_teams.push(TeamAttachment {
                workspace_id: ws.to_string(),
                team: team.to_string(),
            });
        }
        rec.updated_at_ms = chrono::Utc::now().timestamp_millis();
        self.write_secret(&rec)?;
        self.audit_secret_event(
            "secret.attach",
            Some(&rec),
            Some(&format!("team:{}:{}", ws, team)),
        );
        Ok(SecretMeta::from(&rec))
    }

    pub fn detach_secret_from_team(
        &self,
        secret_id: &str,
        workspace_id: &str,
        team: &str,
    ) -> Result<SecretMeta, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let mut rec = self.read_secret(secret_id)?;
        rec.attached_teams
            .retain(|t| !(t.workspace_id == workspace_id.trim() && t.team == team.trim()));
        rec.updated_at_ms = chrono::Utc::now().timestamp_millis();
        self.write_secret(&rec)?;
        self.audit_secret_event(
            "secret.detach",
            Some(&rec),
            Some(&format!("team:{}:{}", workspace_id.trim(), team.trim())),
        );
        Ok(SecretMeta::from(&rec))
    }

    /// Resolve a secret ref to plaintext bytes. This is a privileged internal API.
    pub fn resolve_secret_ref(
        &self,
        secret_ref: &str,
        capability: Option<&str>,
        consumer: Option<&str>,
    ) -> Result<Vec<u8>, VaultError> {
        let cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let sr = SecretRef::parse(secret_ref).map_err(VaultError::Other)?;
        let mut rec = self.read_secret(&sr.secret_id)?;
        if rec.revoked_at_ms.is_some() || rec.ciphertext.is_none() {
            return Err(VaultError::Other("secret revoked".to_string()));
        }
        let kek = self.get_kek(&cfg)?;
        let Some(ciphertext) = rec.ciphertext.as_ref() else {
            return Err(VaultError::Other("secret missing ciphertext".to_string()));
        };
        let aad_value = format!(
            "vault:secret:v1:{}:{}",
            rec.secret_id,
            rec.scope.to_aad_string()
        );
        let aad_value = aad_value.as_bytes();

        let dek_plain =
            aead_decrypt_xchacha20poly1305(&kek, &ciphertext.dek_wrapped.blob, aad_value)
                .map_err(VaultError::Provider)?;
        if dek_plain.len() != 32 {
            return Err(VaultError::Provider("invalid DEK".to_string()));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_plain);
        let value = aead_decrypt_xchacha20poly1305(&dek, &ciphertext.value, aad_value)
            .map_err(VaultError::Provider)?;
        dek.zeroize();

        rec.last_used_at_ms = Some(chrono::Utc::now().timestamp_millis());
        self.write_secret(&rec).ok();
        self.maybe_audit(VaultAuditEvent {
            ts_ms: chrono::Utc::now().timestamp_millis(),
            kind: "secret.used".to_string(),
            secret_id: Some(rec.secret_id.clone()),
            scope: Some(rec.scope.to_display_string()),
            actor: Some("operator".to_string()),
            capability: capability.map(|s| s.to_string()),
            consumer: consumer.map(|s| s.to_string()),
            note: None,
        });
        Ok(value)
    }

    /// Resolve a secret ref for a specific team context (workspace + team).
    ///
    /// This enforces a minimal access policy:
    /// - `team` scope: only that team can use it
    /// - `workspace` scope: any team in the workspace can use it
    /// - `global` scope: only teams explicitly attached can use it
    /// - Any scope can be explicitly shared to a team via `attached_teams`
    pub fn resolve_secret_ref_for_team(
        &self,
        secret_ref: &str,
        workspace_id: &str,
        team: &str,
        capability: Option<&str>,
        consumer: Option<&str>,
    ) -> Result<Vec<u8>, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;

        let ws = workspace_id.trim();
        let team = team.trim();
        if ws.is_empty() || team.is_empty() {
            return Err(VaultError::Other(
                "workspace_id and team are required".to_string(),
            ));
        }

        let sr = SecretRef::parse(secret_ref).map_err(VaultError::Other)?;
        let rec = self.read_secret(&sr.secret_id)?;

        let attached = rec
            .attached_teams
            .iter()
            .any(|t| t.workspace_id == ws && t.team == team);

        let allowed = if attached {
            true
        } else {
            match &rec.scope {
                SecretScope::Global => false,
                SecretScope::Workspace { workspace_id } => workspace_id == ws,
                SecretScope::Team {
                    workspace_id,
                    team: t,
                } => workspace_id == ws && t == team,
            }
        };

        if !allowed {
            self.audit_secret_event(
                "secret.access.denied",
                Some(&rec),
                Some(&format!("team:{}:{}", ws, team)),
            );
            return Err(VaultError::Other("secret not accessible".to_string()));
        }

        self.resolve_secret_ref(secret_ref, capability, consumer)
    }

    /// Lookup a global secret by name (or alias) and return a secret ref.
    pub fn find_global_secret_ref_by_name(
        &self,
        name_or_alias: &str,
    ) -> Result<Option<String>, VaultError> {
        let _cfg = self
            .cfg
            .lock()
            .unwrap()
            .clone()
            .ok_or(VaultError::NotEnabled)?;
        let wanted = name_or_alias.trim();
        if wanted.is_empty() {
            return Ok(None);
        }
        let dir = self.paths.secrets_dir();
        if !dir.exists() {
            return Ok(None);
        }
        let mut matches: Vec<String> = Vec::new();
        let entries = std::fs::read_dir(&dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap_or_default();
            let Ok(rec) = serde_json::from_str::<SecretRecord>(&raw) else {
                continue;
            };
            if !matches!(rec.scope, SecretScope::Global) {
                continue;
            }
            if rec.revoked_at_ms.is_some() {
                continue;
            }
            if rec.name == wanted || rec.aliases.iter().any(|a| a == wanted) {
                matches.push(rec.secret_id);
            }
        }
        if matches.is_empty() {
            return Ok(None);
        }
        // Deterministic winner for legacy conflicts.
        matches.sort();
        matches.dedup();
        Ok(matches.first().map(|secret_id| {
            SecretRef {
                secret_id: secret_id.clone(),
            }
            .to_string()
        }))
    }

    fn get_kek(&self, cfg: &VaultConfig) -> Result<[u8; 32], VaultError> {
        match &cfg.provider {
            VaultProviderConfig::MacosKeychain { service, account } => {
                load_kek_keychain(service, account).map_err(VaultError::Provider)
            }
            VaultProviderConfig::Env { env_var } => {
                load_kek_from_env(env_var).map_err(VaultError::Provider)
            }
            VaultProviderConfig::File { path } => {
                load_kek_from_file(path).map_err(VaultError::Provider)
            }
            VaultProviderConfig::Passphrase { .. } => {
                self.unlocked_kek.lock().unwrap().ok_or(VaultError::Locked)
            }
        }
    }

    fn write_config(&self, cfg: &VaultConfig) -> Result<(), VaultError> {
        let raw = serde_json::to_string_pretty(cfg)?;
        if let Some(parent) = self.paths.config_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(self.paths.config_path(), raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(self.paths.config_path(), perm)?;
        }
        Ok(())
    }

    fn read_secret(&self, secret_id: &str) -> Result<SecretRecord, VaultError> {
        let path = self.paths.secret_path(secret_id);
        if !path.exists() {
            return Err(VaultError::Other("secret not found".to_string()));
        }
        let raw = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str::<SecretRecord>(&raw)?)
    }

    fn write_secret(&self, rec: &SecretRecord) -> Result<(), VaultError> {
        if let Some(parent) = self.paths.secrets_dir().parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::create_dir_all(self.paths.secrets_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_perm = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(self.paths.secrets_dir(), dir_perm)?;
        }
        let raw = serde_json::to_string_pretty(rec)?;
        let path = self.paths.secret_path(&rec.secret_id);
        std::fs::write(&path, raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, file_perm)?;
        }
        Ok(())
    }

    fn audit_secret_event(&self, kind: &str, rec: Option<&SecretRecord>, note: Option<&str>) {
        let ts = chrono::Utc::now().timestamp_millis();
        self.maybe_audit(VaultAuditEvent {
            ts_ms: ts,
            kind: kind.to_string(),
            secret_id: rec.map(|r| r.secret_id.clone()),
            scope: rec.map(|r| r.scope.to_display_string()),
            actor: Some("operator".to_string()),
            capability: None,
            consumer: None,
            note: note.map(|s| s.to_string()),
        });
    }

    fn ensure_name_alias_unique_for_scope(
        &self,
        scope: &SecretScope,
        name: &str,
        aliases: &[String],
        exclude_secret_id: Option<&str>,
    ) -> Result<(), VaultError> {
        if !matches!(scope, SecretScope::Global) {
            return Ok(());
        }
        let dir = self.paths.secrets_dir();
        if !dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap_or_default();
            let Ok(rec) = serde_json::from_str::<SecretRecord>(&raw) else {
                continue;
            };
            if !matches!(rec.scope, SecretScope::Global) {
                continue;
            }
            if let Some(exclude) = exclude_secret_id {
                if rec.secret_id == exclude {
                    continue;
                }
            }
            if rec.name == name || rec.aliases.iter().any(|a| a == name) {
                return Err(VaultError::Other(format!(
                    "global secret name '{}' already exists",
                    name
                )));
            }
            for alias in aliases {
                if rec.name == *alias {
                    return Err(VaultError::Other(format!(
                        "global secret alias '{}' conflicts with existing secret name",
                        alias
                    )));
                }
            }
        }

        Ok(())
    }

    fn rewrap_all_secrets(
        &self,
        old_kek: &[u8; 32],
        new_kek: &[u8; 32],
        new_kek_id: &str,
    ) -> Result<(), VaultError> {
        let dir = self.paths.secrets_dir();
        if !dir.exists() {
            return Ok(());
        }
        let entries = std::fs::read_dir(&dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap_or_default();
            let Ok(mut rec) = serde_json::from_str::<SecretRecord>(&raw) else {
                continue;
            };
            if rec.revoked_at_ms.is_some() {
                continue;
            }
            let Some(ciphertext) = rec.ciphertext.as_mut() else {
                continue;
            };
            let aad_value = format!(
                "vault:secret:v1:{}:{}",
                rec.secret_id,
                rec.scope.to_aad_string()
            );
            let aad_value = aad_value.as_bytes();
            let dek_plain =
                aead_decrypt_xchacha20poly1305(old_kek, &ciphertext.dek_wrapped.blob, aad_value)
                    .map_err(VaultError::Provider)?;
            let wrapped = aead_encrypt_xchacha20poly1305(new_kek, &dek_plain, aad_value)
                .map_err(VaultError::Provider)?;
            ciphertext.dek_wrapped = store::WrappedDekRecord {
                kek_id: new_kek_id.to_string(),
                blob: wrapped,
            };
            rec.updated_at_ms = chrono::Utc::now().timestamp_millis();
            self.write_secret(&rec)?;
        }
        Ok(())
    }
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            let v = value.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn vault_disk_logs_disabled() -> bool {
    env_flag_enabled("AIVAULT_DISABLE_DISK_LOGS") || env_flag_enabled("MOLDABLE_DISABLE_DISK_LOGS")
}

fn normalize_aliases(aliases: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for a in aliases {
        let t = a.trim();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    out.sort();
    out
}

fn parse_key_32(raw: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("missing vault key".to_string());
    }

    // Prefer base64 first (common for env/file).
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed.as_bytes()) {
        if decoded.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&decoded);
            return Ok(out);
        }
    }

    // Hex (64 chars).
    if trimmed.len() == 64 {
        if let Ok(decoded) = hex::decode(trimmed) {
            if decoded.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&decoded);
                return Ok(out);
            }
        }
    }

    Err("invalid vault key (expected base64 or 64-char hex for 32 bytes)".to_string())
}

fn load_kek_from_env(env_var: &str) -> Result<[u8; 32], String> {
    let v = std::env::var(env_var).map_err(|_| format!("missing env var {}", env_var))?;
    parse_key_32(&v)
}

fn load_kek_from_file(path: &str) -> Result<[u8; 32], String> {
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read key file: {}", e))?;
    parse_key_32(&raw)
}

fn store_kek_file(path: &str, kek: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    let p = std::path::PathBuf::from(path);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(kek);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&p)
        .map_err(|e| e.to_string())?;
    f.write_all(b64.as_bytes()).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&p, perm).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn keychain_entry_missing(service: &str, account: &str) -> Result<bool, VaultError> {
    let out = std::process::Command::new("security")
        .args(["find-generic-password", "-a", account, "-s", service, "-w"])
        .output()
        .map_err(|e| VaultError::Provider(e.to_string()))?;
    // security(1) uses exit code 44 for "item not found".
    if out.status.code() == Some(44) {
        return Ok(true);
    }
    if out.status.success() {
        return Ok(false);
    }
    Err(VaultError::Provider(
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

#[cfg(not(target_os = "macos"))]
fn keychain_entry_missing(service: &str, account: &str) -> Result<bool, VaultError> {
    match load_kek_keychain_password(service, account) {
        Ok(_) => Ok(false),
        Err(keyring::Error::NoEntry) => Ok(true),
        Err(err) => Err(VaultError::Provider(err.to_string())),
    }
}

#[cfg(target_os = "macos")]
fn store_kek_keychain(service: &str, account: &str, kek: &[u8; 32]) -> Result<(), VaultError> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(kek);
    let out = std::process::Command::new("security")
        .args([
            "add-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            &b64,
            "-U",
        ])
        .output()
        .map_err(|e| VaultError::Provider(e.to_string()))?;
    if !out.status.success() {
        return Err(VaultError::Provider(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn store_kek_keychain(service: &str, account: &str, kek: &[u8; 32]) -> Result<(), VaultError> {
    let entry =
        keyring::Entry::new(service, account).map_err(|e| VaultError::Provider(e.to_string()))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(kek);
    entry
        .set_password(&b64)
        .map_err(|e| VaultError::Provider(e.to_string()))?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn load_kek_keychain_password(service: &str, account: &str) -> Result<String, keyring::Error> {
    let entry = keyring::Entry::new(service, account)?;
    entry.get_password()
}

#[cfg(target_os = "macos")]
fn load_kek_keychain(service: &str, account: &str) -> Result<[u8; 32], String> {
    let out = std::process::Command::new("security")
        .args(["find-generic-password", "-a", account, "-s", service, "-w"])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.code() == Some(44) {
        return Err("No matching entry found in secure storage".to_string());
    }
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let b64 = String::from_utf8(out.stdout).map_err(|e| e.to_string())?;
    parse_key_32(&b64)
}

#[cfg(not(target_os = "macos"))]
fn load_kek_keychain(service: &str, account: &str) -> Result<[u8; 32], String> {
    let b64 = load_kek_keychain_password(service, account).map_err(|e| e.to_string())?;
    parse_key_32(&b64)
}

impl VaultRuntime {
    fn ensure_default_initialized(&self) -> Result<(), VaultError> {
        // Another thread/process may have initialized already.
        if self.paths.config_path().exists() {
            return self.load();
        }

        // Serialize first-run initialization across threads/processes.
        let _lock = self.acquire_init_lock()?;
        if self.paths.config_path().exists() {
            return self.load();
        }

        let is_override_dir = ["AIVAULT_DIR"].iter().any(|var| {
            std::env::var(var)
                .ok()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
        });

        // Only use Keychain by default when we're using the canonical home vault location.
        // This avoids tests/temp state dirs writing to the user's Keychain.
        let canonical_home = VaultPaths::discover().root_dir;
        let is_canonical_home = self.paths.root_dir == canonical_home;

        // Default provider:
        // - macOS: Keychain (best UX)
        // - other: file-based key inside the vault dir (seamless local ops)
        let default_provider = if cfg!(target_os = "macos") && !is_override_dir && is_canonical_home
        {
            VaultProviderConfig::MacosKeychain {
                service: "aivault".to_string(),
                account: "kek".to_string(),
            }
        } else {
            let key_path = self.paths.root_dir().join("kek.key").display().to_string();
            VaultProviderConfig::File { path: key_path }
        };

        // Best-effort init with fallback to file provider on macOS if Keychain fails.
        let init_res = self.init_unlocked(default_provider);
        if init_res.is_err() && cfg!(target_os = "macos") {
            let key_path = self.paths.root_dir().join("kek.key").display().to_string();
            let _ = self.init_unlocked(VaultProviderConfig::File { path: key_path })?;
        } else {
            init_res?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScopedEnvVar, ENV_LOCK};

    #[test]
    fn env_provider_create_and_resolve_secret() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-test", SecretScope::Global, vec![])
            .unwrap();
        assert!(!meta.system_managed);
        let sr = SecretRef {
            secret_id: meta.secret_id.clone(),
        }
        .to_string();
        let value = vault
            .resolve_secret_ref(&sr, Some("test"), Some("unit"))
            .unwrap();
        assert_eq!(value, b"sk-test".to_vec());
    }

    #[test]
    fn system_secrets_are_persisted_as_system_managed() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_system_secret("GATEWAY_AUTH_TOKEN", b"t-1", SecretScope::Global, vec![])
            .unwrap();
        assert!(meta.system_managed);

        // Validate on-disk record carries the flag.
        let raw = std::fs::read_to_string(vault.paths().secret_path(&meta.secret_id)).unwrap();
        let rec: SecretRecord = serde_json::from_str(&raw).unwrap();
        assert!(rec.system_managed);
    }

    #[test]
    fn team_scoped_resolution_enforces_attachments_for_global() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("GLOBAL_TOKEN", b"t-1", SecretScope::Global, vec![])
            .unwrap();
        let sr = SecretRef {
            secret_id: meta.secret_id.clone(),
        }
        .to_string();

        // Global secrets are not available to teams unless explicitly attached.
        assert!(vault
            .resolve_secret_ref_for_team(&sr, "default", "support", Some("cap"), Some("team"))
            .is_err());

        vault
            .attach_secret_to_team(&meta.secret_id, "default", "support")
            .unwrap();
        let value = vault
            .resolve_secret_ref_for_team(&sr, "default", "support", Some("cap"), Some("team"))
            .unwrap();
        assert_eq!(value, b"t-1".to_vec());
    }

    #[test]
    fn passphrase_unlocks_and_locks() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        // Vault is auto-initialized with a seamless provider; switch to passphrase mode.
        vault.rotate_master_key(None, Some("pw")).unwrap();
        vault.lock().unwrap();
        assert!(vault
            .create_secret("x", b"y", SecretScope::Global, vec![])
            .is_err());
        vault.unlock("pw").unwrap();
        vault
            .create_secret("x", b"y", SecretScope::Global, vec![])
            .unwrap();
    }

    #[test]
    fn load_auto_initializes_default_file_provider_in_override_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        let status = vault.status();
        assert!(status.enabled);
        assert!(!status.locked);

        let cfg_raw = std::fs::read_to_string(vault.paths().config_path()).unwrap();
        let cfg: VaultConfig = serde_json::from_str(&cfg_raw).unwrap();
        assert!(matches!(cfg.provider, VaultProviderConfig::File { .. }));

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-auto", SecretScope::Global, vec![])
            .unwrap();
        let sr = SecretRef {
            secret_id: meta.secret_id,
        }
        .to_string();
        let value = vault
            .resolve_secret_ref(&sr, Some("test.auto_init"), Some("unit"))
            .unwrap();
        assert_eq!(value, b"sk-auto".to_vec());
    }

    #[test]
    fn update_secret_meta_changes_name_and_aliases() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-old", SecretScope::Global, vec![])
            .unwrap();
        let updated = vault
            .update_secret_meta(
                &meta.secret_id,
                Some("OPENAI_API_KEY_NEW".to_string()),
                Some(vec!["OPENAI_KEY".to_string(), "OAI_KEY".to_string()]),
            )
            .unwrap();
        assert_eq!(updated.secret_id, meta.secret_id);
        assert_eq!(updated.name, "OPENAI_API_KEY_NEW");
        let mut aliases = updated.aliases.clone();
        aliases.sort();
        assert_eq!(aliases, vec!["OAI_KEY", "OPENAI_KEY"]);
    }

    #[test]
    fn rotate_secret_value_increments_version_and_keeps_id() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-v1", SecretScope::Global, vec![])
            .unwrap();
        assert_eq!(meta.value_version, 1);
        let rotated = vault
            .rotate_secret_value(&meta.secret_id, b"sk-v2")
            .unwrap();
        assert_eq!(rotated.secret_id, meta.secret_id);
        assert_eq!(rotated.value_version, 2);

        let sr = SecretRef {
            secret_id: meta.secret_id,
        }
        .to_string();
        let value = vault
            .resolve_secret_ref(&sr, Some("test.rotate_secret"), Some("unit"))
            .unwrap();
        assert_eq!(value, b"sk-v2".to_vec());
    }

    #[test]
    fn revoke_secret_clears_ciphertext_and_blocks_resolution() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-live", SecretScope::Global, vec![])
            .unwrap();
        let revoked = vault.revoke_secret(&meta.secret_id).unwrap();
        assert!(revoked.revoked_at_ms.is_some());

        let raw = std::fs::read_to_string(vault.paths().secret_path(&meta.secret_id)).unwrap();
        let rec: SecretRecord = serde_json::from_str(&raw).unwrap();
        assert!(rec.ciphertext.is_none());

        let sr = SecretRef {
            secret_id: meta.secret_id,
        }
        .to_string();
        assert!(vault
            .resolve_secret_ref(&sr, Some("test.revoke"), Some("unit"))
            .is_err());
    }

    #[test]
    fn team_and_workspace_scope_resolution_matrix_and_detach() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let ws = vault
            .create_secret(
                "WORKSPACE_TOKEN",
                b"w-1",
                SecretScope::Workspace {
                    workspace_id: "default".to_string(),
                },
                vec![],
            )
            .unwrap();
        let team = vault
            .create_secret(
                "TEAM_TOKEN",
                b"t-1",
                SecretScope::Team {
                    workspace_id: "default".to_string(),
                    team: "support".to_string(),
                },
                vec![],
            )
            .unwrap();
        let global = vault
            .create_secret("GLOBAL_TOKEN", b"g-1", SecretScope::Global, vec![])
            .unwrap();

        let ws_ref = SecretRef {
            secret_id: ws.secret_id,
        }
        .to_string();
        let team_ref = SecretRef {
            secret_id: team.secret_id,
        }
        .to_string();
        let global_ref = SecretRef {
            secret_id: global.secret_id.clone(),
        }
        .to_string();

        let ws_support = vault
            .resolve_secret_ref_for_team(&ws_ref, "default", "support", Some("cap"), Some("team"))
            .unwrap();
        assert_eq!(ws_support, b"w-1".to_vec());
        let ws_sales = vault
            .resolve_secret_ref_for_team(&ws_ref, "default", "sales", Some("cap"), Some("team"))
            .unwrap();
        assert_eq!(ws_sales, b"w-1".to_vec());
        assert!(vault
            .resolve_secret_ref_for_team(&ws_ref, "other", "support", Some("cap"), Some("team"))
            .is_err());

        let team_support = vault
            .resolve_secret_ref_for_team(&team_ref, "default", "support", Some("cap"), Some("team"))
            .unwrap();
        assert_eq!(team_support, b"t-1".to_vec());
        assert!(vault
            .resolve_secret_ref_for_team(&team_ref, "default", "sales", Some("cap"), Some("team"))
            .is_err());
        assert!(vault
            .resolve_secret_ref_for_team(&team_ref, "other", "support", Some("cap"), Some("team"))
            .is_err());

        assert!(vault
            .resolve_secret_ref_for_team(
                &global_ref,
                "default",
                "support",
                Some("cap"),
                Some("team"),
            )
            .is_err());
        vault
            .attach_secret_to_team(&global.secret_id, "default", "support")
            .unwrap();
        let global_support = vault
            .resolve_secret_ref_for_team(
                &global_ref,
                "default",
                "support",
                Some("cap"),
                Some("team"),
            )
            .unwrap();
        assert_eq!(global_support, b"g-1".to_vec());
        vault
            .detach_secret_from_team(&global.secret_id, "default", "support")
            .unwrap();
        assert!(vault
            .resolve_secret_ref_for_team(
                &global_ref,
                "default",
                "support",
                Some("cap"),
                Some("team"),
            )
            .is_err());
    }

    #[test]
    fn create_secret_rejects_duplicate_global_name_or_alias() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );
        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        vault
            .create_secret(
                "OPENAI_API_KEY",
                b"sk-a",
                SecretScope::Global,
                vec!["OAI_KEY".to_string()],
            )
            .unwrap();

        let err = vault
            .create_secret("OPENAI_API_KEY", b"sk-b", SecretScope::Global, vec![])
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));

        let err = vault
            .create_secret("OAI_KEY", b"sk-c", SecretScope::Global, vec![])
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));

        // Non-global scopes are allowed to reuse names.
        let ws = vault
            .create_secret(
                "OPENAI_API_KEY",
                b"ws-a",
                SecretScope::Workspace {
                    workspace_id: "default".to_string(),
                },
                vec![],
            )
            .unwrap();
        assert_eq!(ws.name, "OPENAI_API_KEY");
    }

    #[test]
    fn update_secret_rejects_duplicate_global_name_or_alias() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );
        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let a = vault
            .create_secret(
                "ANTHROPIC_API_KEY",
                b"ak-a",
                SecretScope::Global,
                vec!["ANTHROPIC_KEY".to_string()],
            )
            .unwrap();
        let b = vault
            .create_secret("OPENAI_API_KEY", b"ok-b", SecretScope::Global, vec![])
            .unwrap();

        let err = vault
            .update_secret_meta(&b.secret_id, Some(a.name.clone()), None)
            .unwrap_err();
        assert!(err.to_string().contains("already exists"));

        let err = vault
            .update_secret_meta(
                &b.secret_id,
                None,
                Some(vec!["ANTHROPIC_API_KEY".to_string()]),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("conflicts") || err.to_string().contains("already exists")
        );
    }

    #[test]
    fn find_global_secret_ref_by_name_is_deterministic_for_legacy_conflicts() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );
        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let first = vault
            .create_secret("OPENAI_API_KEY_A", b"a", SecretScope::Global, vec![])
            .unwrap();
        let second = vault
            .create_secret("OPENAI_API_KEY_B", b"b", SecretScope::Global, vec![])
            .unwrap();

        // Simulate pre-existing conflicting data from an older version by editing the raw records.
        let first_path = vault.paths().secret_path(&first.secret_id);
        let second_path = vault.paths().secret_path(&second.secret_id);
        let mut first_rec: SecretRecord =
            serde_json::from_str(&std::fs::read_to_string(&first_path).unwrap()).unwrap();
        let mut second_rec: SecretRecord =
            serde_json::from_str(&std::fs::read_to_string(&second_path).unwrap()).unwrap();
        first_rec.aliases = vec!["OPENAI_SHARED".to_string()];
        second_rec.aliases = vec!["OPENAI_SHARED".to_string()];
        std::fs::write(
            &first_path,
            serde_json::to_string_pretty(&first_rec).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &second_path,
            serde_json::to_string_pretty(&second_rec).unwrap(),
        )
        .unwrap();

        let a = vault
            .find_global_secret_ref_by_name("OPENAI_SHARED")
            .unwrap()
            .unwrap();
        let b = vault
            .find_global_secret_ref_by_name("OPENAI_SHARED")
            .unwrap()
            .unwrap();
        assert_eq!(a, b);

        let expected = if first.secret_id < second.secret_id {
            first.secret_id
        } else {
            second.secret_id
        };
        assert_eq!(
            a,
            SecretRef {
                secret_id: expected
            }
            .to_string()
        );
    }

    #[test]
    fn rotate_master_key_rewraps_existing_ciphertext() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault.init_passphrase("pw-old").unwrap();

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-before", SecretScope::Global, vec![])
            .unwrap();
        let before_raw =
            std::fs::read_to_string(vault.paths().secret_path(&meta.secret_id)).unwrap();
        let before_rec: SecretRecord = serde_json::from_str(&before_raw).unwrap();
        let before_cipher = before_rec.ciphertext.clone().unwrap();

        let _ = vault.rotate_master_key(None, Some("pw-new")).unwrap();

        let after_raw =
            std::fs::read_to_string(vault.paths().secret_path(&meta.secret_id)).unwrap();
        let after_rec: SecretRecord = serde_json::from_str(&after_raw).unwrap();
        let after_cipher = after_rec.ciphertext.clone().unwrap();
        assert_ne!(
            before_cipher.dek_wrapped.kek_id,
            after_cipher.dek_wrapped.kek_id
        );
        assert_ne!(
            before_cipher.dek_wrapped.blob.ciphertext_b64,
            after_cipher.dek_wrapped.blob.ciphertext_b64
        );
        vault.lock().unwrap();
        assert!(vault.unlock("pw-old").is_err());
        vault.unlock("pw-new").unwrap();

        let sr = SecretRef {
            secret_id: meta.secret_id.clone(),
        }
        .to_string();
        let value = vault
            .resolve_secret_ref(&sr, Some("test.rotate"), Some("unit"))
            .unwrap();
        assert_eq!(value, b"sk-before".to_vec());
    }

    #[test]
    #[cfg(unix)]
    fn store_kek_file_sets_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("kek.key");
        let key = random_key_32();
        store_kek_file(
            key_path
                .to_str()
                .expect("temp key path should be valid utf-8"),
            &key,
        )
        .unwrap();
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn secret_files_are_not_plaintext_and_use_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret(
                "OPENAI_API_KEY",
                b"sk-test-plaintext",
                SecretScope::Global,
                vec![],
            )
            .unwrap();
        let secret_path = vault.paths().secret_path(&meta.secret_id);
        let raw = std::fs::read_to_string(&secret_path).unwrap();
        assert!(!raw.contains("sk-test-plaintext"));

        let rec: SecretRecord = serde_json::from_str(&raw).unwrap();
        assert!(rec.ciphertext.is_some());

        let file_mode = std::fs::metadata(&secret_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);

        let dir_mode = std::fs::metadata(vault.paths().secrets_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn set_audit_enabled_false_stops_new_audit_writes() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = random_key_32();
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();
        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-test", SecretScope::Global, vec![])
            .unwrap();
        let sr = SecretRef {
            secret_id: meta.secret_id,
        }
        .to_string();

        let before = read_audit_events(&vault.paths().audit_dir(), 1000)
            .unwrap()
            .len();
        vault.set_audit_enabled(false);
        vault
            .resolve_secret_ref(&sr, Some("test.audit"), Some("unit"))
            .unwrap();
        let after = read_audit_events(&vault.paths().audit_dir(), 1000)
            .unwrap()
            .len();
        assert_eq!(after, before);
    }
}
