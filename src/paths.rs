use std::path::PathBuf;

/// Best-effort home directory resolution.
///
/// We prefer `dirs::home_dir()`, but that can return `None` in some service/test
/// environments. In those cases, fall back to common environment variables.
pub fn user_home_dir() -> Option<PathBuf> {
    dirs::home_dir()
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

/// Return the base `.aivault` directory.
///
/// If the user's home directory can't be resolved, we fall back to an absolute
/// temp directory to avoid writing into the current working directory.
pub fn aivault_root_dir() -> PathBuf {
    if let Some(home) = user_home_dir() {
        home.join(".aivault")
    } else {
        std::env::temp_dir().join("aivault-no-home")
    }
}

/// Return the canonical AIVault data directory.
pub fn aivault_data_dir() -> PathBuf {
    aivault_root_dir().join("data")
}
