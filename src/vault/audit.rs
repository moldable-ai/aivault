use std::path::Path;

use chrono::Datelike;
use serde::{Deserialize, Serialize};

use crate::log_retention::rotate_path_by_size;

// Keep audit logs bounded on disk similar to `gateway.log`.
// This is intentionally not user-configurable yet; we can wire it to config if/when needed.
const VAULT_AUDIT_MAX_FILES: usize = 10;
const VAULT_AUDIT_MAX_SIZE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultAuditEvent {
    pub ts_ms: i64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn append_audit_event(audit_dir: &Path, event: &VaultAuditEvent) -> Result<(), String> {
    let ts = chrono::Utc::now();
    let filename = format!("{}-{:02}.jsonl", ts.year(), ts.month());
    let path = audit_dir.join(filename);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let line = serde_json::to_string(event).map_err(|e| e.to_string())? + "\n";
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    let _ = rotate_path_by_size(&path, VAULT_AUDIT_MAX_FILES, VAULT_AUDIT_MAX_SIZE_BYTES);
    Ok(())
}

pub fn read_audit_events(audit_dir: &Path, limit: usize) -> Result<Vec<VaultAuditEvent>, String> {
    read_audit_events_before(audit_dir, limit, None)
}

#[derive(Debug, Clone)]
struct AuditFileKey {
    // Primary sortable prefix (e.g. "2026-02" from "2026-02.jsonl.1").
    prefix: String,
    // Rotation index: 0 = base file, 1 = ".1", etc. Higher numbers are older.
    rotation_idx: u32,
    // Fallback to stabilize ordering for unrecognized names.
    file_name: String,
}

fn audit_file_key(path: &std::path::Path) -> AuditFileKey {
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if let Some((prefix, rest)) = file_name.split_once(".jsonl") {
        let rotation_idx = rest
            .strip_prefix('.')
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        return AuditFileKey {
            prefix: prefix.to_string(),
            rotation_idx,
            file_name,
        };
    }
    AuditFileKey {
        prefix: file_name.clone(),
        rotation_idx: 0,
        file_name,
    }
}

pub fn read_audit_events_before(
    audit_dir: &Path,
    limit: usize,
    before_ts_ms: Option<i64>,
) -> Result<Vec<VaultAuditEvent>, String> {
    if !audit_dir.exists() {
        return Ok(Vec::new());
    }
    let mut files: Vec<_> = std::fs::read_dir(audit_dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    // Newest first by (prefix desc, rotation idx asc). Base file (idx 0) is newest within a prefix.
    files.sort_by(|a, b| {
        let ak = audit_file_key(a);
        let bk = audit_file_key(b);
        bk.prefix
            .cmp(&ak.prefix)
            .then_with(|| ak.rotation_idx.cmp(&bk.rotation_idx))
            .then_with(|| bk.file_name.cmp(&ak.file_name))
    });

    let mut out = Vec::new();
    for path in files {
        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        for line in raw.lines().rev() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(evt) = serde_json::from_str::<VaultAuditEvent>(line) {
                if let Some(before) = before_ts_ms {
                    if evt.ts_ms >= before {
                        continue;
                    }
                }
                out.push(evt);
                if out.len() >= limit {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(ts_ms: i64, kind: &str) -> VaultAuditEvent {
        VaultAuditEvent {
            ts_ms,
            kind: kind.to_string(),
            secret_id: Some("sec-1".to_string()),
            scope: Some("global".to_string()),
            actor: Some("operator".to_string()),
            capability: None,
            consumer: None,
            note: None,
        }
    }

    #[test]
    fn read_audit_events_before_orders_newest_first_across_rotated_files() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path();

        let feb = audit_dir.join("2026-02.jsonl");
        let feb_rot = audit_dir.join("2026-02.jsonl.1");
        let jan = audit_dir.join("2026-01.jsonl");

        std::fs::write(
            &feb,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&evt(190, "secret.create")).unwrap(),
                serde_json::to_string(&evt(200, "secret.rotate")).unwrap()
            ),
        )
        .unwrap();
        std::fs::write(
            &feb_rot,
            format!(
                "{}\n",
                serde_json::to_string(&evt(180, "secret.update")).unwrap()
            ),
        )
        .unwrap();
        std::fs::write(
            &jan,
            format!(
                "{}\n",
                serde_json::to_string(&evt(170, "secret.revoke")).unwrap()
            ),
        )
        .unwrap();

        let out = read_audit_events(audit_dir, 10).unwrap();
        let ts: Vec<i64> = out.into_iter().map(|e| e.ts_ms).collect();
        assert_eq!(ts, vec![200, 190, 180, 170]);
    }

    #[test]
    fn read_audit_events_before_respects_cursor_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path();
        let p = audit_dir.join("2026-02.jsonl");
        std::fs::write(
            &p,
            format!(
                "{}\n{}\n{}\n",
                serde_json::to_string(&evt(101, "a")).unwrap(),
                serde_json::to_string(&evt(102, "b")).unwrap(),
                serde_json::to_string(&evt(103, "c")).unwrap()
            ),
        )
        .unwrap();

        let out = read_audit_events_before(audit_dir, 2, Some(103)).unwrap();
        let ts: Vec<i64> = out.into_iter().map(|e| e.ts_ms).collect();
        assert_eq!(ts, vec![102, 101]);
    }

    #[test]
    fn append_audit_event_rotates_when_file_exceeds_limit() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path();
        let now = chrono::Utc::now();
        let base_name = format!("{}-{:02}.jsonl", now.year(), now.month());
        let p = audit_dir.join(&base_name);
        std::fs::create_dir_all(audit_dir).unwrap();
        std::fs::write(&p, vec![b'x'; (5 * 1024 * 1024) as usize]).unwrap();

        append_audit_event(audit_dir, &evt(999, "secret.create")).unwrap();
        assert!(audit_dir.join(format!("{}.1", base_name)).exists());
    }
}
