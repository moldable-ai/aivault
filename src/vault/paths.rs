use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub root_dir: PathBuf,
}

fn env_vault_dir_override() -> Option<PathBuf> {
    for var in ["AIVAULT_DIR"] {
        if let Ok(dir) = std::env::var(var) {
            let trimmed = dir.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    None
}

impl VaultPaths {
    pub fn discover() -> Self {
        if let Some(root_dir) = env_vault_dir_override() {
            return Self { root_dir };
        }

        // Canonical shared vault location:
        // ~/.aivault/data/vault
        let root_dir = crate::paths::aivault_data_dir().join("vault");
        Self { root_dir }
    }

    /// Derive a vault location from a state dir.
    ///
    /// This keeps local installs at `~/.aivault/data/vault` while allowing tests to use
    /// isolated temp dirs.
    pub fn for_gateway_state_dir(state_dir: &Path) -> Self {
        if let Some(root_dir) = env_vault_dir_override() {
            return Self { root_dir };
        }

        // Common test/dev layouts:
        // - <tmp>/state -> <tmp>/shared/vault
        // - <tmp>/gateway/state -> <tmp>/shared/vault
        let mut base = state_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| state_dir.to_path_buf());

        if state_dir.file_name().and_then(|s| s.to_str()) == Some("state")
            && state_dir
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                == Some("gateway")
        {
            if let Some(p) = state_dir.parent().and_then(|p| p.parent()) {
                base = p.to_path_buf();
            }
        }

        Self {
            root_dir: base.join("shared").join("vault"),
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.root_dir.join("vault.json")
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.root_dir.join("secrets")
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.root_dir.join("audit")
    }

    pub fn secret_path(&self, secret_id: &str) -> PathBuf {
        self.secrets_dir().join(format!("{}.json", secret_id))
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root_dir)?;
        std::fs::create_dir_all(self.secrets_dir())?;
        std::fs::create_dir_all(self.audit_dir())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_perm = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(&self.root_dir, dir_perm);
        }
        Ok(())
    }

    pub fn is_enabled(&self) -> bool {
        self.config_path().exists()
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }
}
