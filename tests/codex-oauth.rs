#![cfg(debug_assertions)]

use aivault::codex_oauth::prepare_codex_oauth_access;
use aivault::vault::{SecretRef, SecretScope, VaultPaths, VaultProviderConfig, VaultRuntime};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn codex_refresh_process_worker() {
    let Ok(secret_ref) = std::env::var("AIVAULT_CODEX_TEST_REF") else {
        return;
    };
    let vault = VaultRuntime::discover();
    vault.load().unwrap();
    let ready = std::env::var("AIVAULT_CODEX_TEST_READY").unwrap();
    std::fs::write(&ready, b"ready").unwrap();
    let start = Instant::now();
    while !std::path::Path::new(&std::env::var("AIVAULT_CODEX_TEST_GO").unwrap()).exists() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(5));
    }
    let access = prepare_codex_oauth_access(&vault, &secret_ref).unwrap();
    assert_eq!(access.access_token, "rotated-access");
}

#[test]
fn codex_refresh_is_serialized_across_processes_and_survives_concurrent_reads() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("test-key");
    std::fs::write(&keyfile, "07".repeat(32)).unwrap();
    let vault = VaultRuntime::new(VaultPaths {
        root_dir: dir.path().to_path_buf(),
    });
    vault
        .init(VaultProviderConfig::File {
            path: keyfile.to_string_lossy().into_owned(),
        })
        .unwrap();
    let meta = vault.create_system_secret("CODEX_OAUTH_JSON",
        br#"{"access_token":"old","refresh_token":"old-refresh","expires_at":0,"account_id":"account"}"#,
        SecretScope::Global, Vec::new()).unwrap();
    let secret_ref = SecretRef {
        secret_id: meta.secret_id.clone(),
    }
    .to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/oauth/token", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let server_finished = finished.clone();
    let server_requests = requests.clone();
    let server = std::thread::spawn(move || {
        while !server_finished.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = [0; 8192];
                    let n = stream.read(&mut bytes).unwrap();
                    assert!(String::from_utf8_lossy(&bytes[..n]).contains("POST /oauth/token"));
                    server_requests.fetch_add(1, Ordering::SeqCst);
                    // Hold the rotation open while the other process reaches refresh.
                    std::thread::sleep(Duration::from_millis(200));
                    let body = r#"{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}"#;
                    write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("{error}"),
            }
        }
    });
    let go = dir.path().join("go");
    let mut children = Vec::new();
    let mut ready_files = Vec::new();
    for worker in 0..3 {
        let ready = dir.path().join(format!("ready-{worker}"));
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "codex_refresh_process_worker", "--nocapture"])
                .env("AIVAULT_DIR", dir.path())
                .env("AIVAULT_DEV_ALLOW_HTTP_LOCAL", "1")
                .env("AIVAULT_DEV_CODEX_OAUTH_TOKEN_ENDPOINT", &endpoint)
                .env("AIVAULT_CODEX_TEST_REF", &secret_ref)
                .env("AIVAULT_CODEX_TEST_READY", &ready)
                .env("AIVAULT_CODEX_TEST_GO", &go)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        ready_files.push(ready);
    }
    let start = Instant::now();
    while !ready_files.iter().all(|ready| ready.exists()) {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::write(&go, b"go").unwrap();
    let reader_vault = vault.clone();
    let reader_ref = secret_ref.clone();
    let reader_finished = finished.clone();
    let reader = std::thread::spawn(move || {
        while !reader_finished.load(Ordering::SeqCst) {
            reader_vault
                .resolve_secret_ref(&reader_ref, None, None)
                .unwrap();
        }
    });
    let results = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    finished.store(true, Ordering::SeqCst);
    reader.join().unwrap();
    server.join().unwrap();
    for result in results {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert_eq!(
        requests.load(Ordering::SeqCst),
        1,
        "one rotating refresh token must be consumed once"
    );
    assert_eq!(
        vault
            .get_secret_meta(&meta.secret_id)
            .unwrap()
            .value_version,
        2
    );
    let raw = vault.resolve_secret_ref(&secret_ref, None, None).unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(stored["refresh_token"], "rotated-refresh");
}
