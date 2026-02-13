#[cfg(test)]
use std::{
    ffi::{OsStr, OsString},
    sync::Mutex,
};

#[cfg(test)]
pub static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard for temporarily setting/removing an environment variable in tests.
///
/// IMPORTANT: This does not prevent other tests from mutating the environment.
/// Pair usage with `ENV_LOCK` when the variable is shared/global (e.g. HOME).
#[cfg(test)]
pub struct ScopedEnvVar {
    key: String,
    old: Option<OsString>,
}

#[cfg(test)]
impl ScopedEnvVar {
    pub fn set(key: &str, value: impl AsRef<OsStr>) -> Self {
        let old = std::env::var_os(key);
        std::env::set_var(key, value);
        Self {
            key: key.to_string(),
            old,
        }
    }

    pub fn remove(key: &str) -> Self {
        let old = std::env::var_os(key);
        std::env::remove_var(key);
        Self {
            key: key.to_string(),
            old,
        }
    }
}

#[cfg(test)]
impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match &self.old {
            Some(v) => std::env::set_var(&self.key, v),
            None => std::env::remove_var(&self.key),
        }
    }
}
