use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Rotate `path` into `path.1`, `path.2`, ... when it exceeds `max_size_bytes`.
///
/// Rotation scheme:
/// - `path` -> `path.1`
/// - `path.1` -> `path.2`
/// - ...
/// - deletes `path.{max_files}` (if it exists)
///
/// Notes:
/// - This is best-effort and safe to call repeatedly.
/// - If `max_files == 0` or `max_size_bytes == 0`, rotation is disabled.
pub fn rotate_path_by_size(path: &Path, max_files: usize, max_size_bytes: u64) -> io::Result<()> {
    if max_files == 0 || max_size_bytes == 0 {
        return Ok(());
    }
    if !path.exists() {
        return Ok(());
    }

    let meta = fs::metadata(path)?;
    if meta.len() < max_size_bytes {
        return Ok(());
    }

    let max = max_files.clamp(1, 20);
    for idx in (1..=max).rev() {
        let rotated = rotated_path(path, idx);
        if rotated.exists() {
            if idx == max {
                let _ = fs::remove_file(&rotated);
            } else {
                let next = rotated_path(path, idx + 1);
                let _ = fs::rename(&rotated, &next);
            }
        }
    }

    let first = rotated_path(path, 1);
    let _ = fs::rename(path, &first);
    Ok(())
}

fn rotated_path(base: &Path, idx: usize) -> PathBuf {
    PathBuf::from(format!("{}.{}", base.to_string_lossy(), idx))
}

/// Prune files in `dir` to keep at most `max_files` entries matching `predicate`.
///
/// Keeps the "newest" files by lexicographic filename order (descending). This works well when
/// filenames include sortable timestamps (e.g. `agent_YYYYMMDD_HHMMSS.jsonl`).
pub fn prune_dir_by_name(
    dir: &Path,
    max_files: usize,
    predicate: impl Fn(&Path) -> bool,
) -> io::Result<usize> {
    if max_files == 0 {
        // Caller explicitly wants to keep nothing; still be safe and just skip pruning.
        return Ok(0);
    }
    if !dir.exists() {
        return Ok(0);
    }

    let mut files: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !predicate(&path) {
            continue;
        }
        files.push(path);
    }

    // Sort by filename (descending) so we keep the newest (largest) names first.
    files.sort_by(|a, b| {
        let an = a.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let bn = b.file_name().and_then(|s| s.to_str()).unwrap_or("");
        bn.cmp(an)
    });

    if files.len() <= max_files {
        return Ok(0);
    }

    let mut removed = 0usize;
    for path in files.into_iter().skip(max_files) {
        if fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_path_by_size_moves_large_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("gateway.log");
        fs::write(&p, vec![0u8; 1024 * 1024]).unwrap();

        rotate_path_by_size(&p, 3, 1).unwrap();
        assert!(dir.path().join("gateway.log.1").exists());
    }

    #[test]
    fn prune_dir_by_name_keeps_newest() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("a_20260101_000001.jsonl"), "x").unwrap();
        fs::write(d.join("a_20260101_000002.jsonl"), "y").unwrap();
        fs::write(d.join("a_20260101_000003.jsonl"), "z").unwrap();

        let removed = prune_dir_by_name(d, 2, |p| {
            p.extension().and_then(|e| e.to_str()) == Some("jsonl")
        })
        .unwrap();
        assert_eq!(removed, 1);
        assert!(!d.join("a_20260101_000001.jsonl").exists());
        assert!(d.join("a_20260101_000003.jsonl").exists());
    }
}
