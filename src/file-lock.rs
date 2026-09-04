use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::Path;

/// Keep the lock inode stable: unlinking it would let another process lock a
/// different file while an existing holder is still updating the same secret.
pub(crate) fn lock(root: &Path, namespace: &str, key: &str) -> std::io::Result<File> {
    let directory = root.join("locks");
    std::fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let filename = format!("{namespace}-{}.lock", hex::encode(Sha256::digest(key)));
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(directory.join(filename))?;
    file.lock()?;
    Ok(file)
}
