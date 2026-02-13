use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};

use axum::routing::any;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use serde_json::Value;
use tempfile::TempDir;
use tokio::runtime::Builder as TokioRuntimeBuilder;

fn install_rustls_provider_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

struct LocalTlsServer {
    host: String,
    addr: SocketAddr,
    cert_pem_path: PathBuf,
    handle: axum_server::Handle,
    thread: Option<thread::JoinHandle<()>>,
    _cert_dir: TempDir,
}

impl LocalTlsServer {
    fn start(host: &str) -> Self {
        install_rustls_provider_once();

        let cert = generate_simple_self_signed(vec![host.to_string()]).expect("generate cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let cert_dir = TempDir::new().expect("cert temp dir");
        let cert_pem_path = cert_dir.path().join("cert.pem");
        let key_pem_path = cert_dir.path().join("key.pem");
        std::fs::write(&cert_pem_path, cert_pem).expect("write cert pem");
        std::fs::write(&key_pem_path, key_pem).expect("write key pem");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let handle = axum_server::Handle::new();
        let handle_for_thread = handle.clone();

        let cert_path_for_thread = cert_pem_path.clone();
        let key_path_for_thread = key_pem_path.clone();

        let thread = thread::spawn(move || {
            let runtime = TokioRuntimeBuilder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");
            runtime.block_on(async move {
                let app =
                    Router::new().fallback(any(|| async { Json(serde_json::json!({"ok": true})) }));
                let tls_config =
                    RustlsConfig::from_pem_file(cert_path_for_thread, key_path_for_thread)
                        .await
                        .expect("load rustls config");
                let server = axum_server::bind_rustls(addr, tls_config)
                    .handle(handle_for_thread)
                    .serve(app.into_make_service());
                let _ = server.await;
            });
        });

        wait_until_listener_ready(addr);

        Self {
            host: host.to_string(),
            addr,
            cert_pem_path,
            handle,
            thread: Some(thread),
            _cert_dir: cert_dir,
        }
    }

    fn env_pairs(&self) -> Vec<(String, String)> {
        vec![
            (
                "AIVAULT_DEV_RESOLVE".to_string(),
                format!("{}={}", self.host, self.addr),
            ),
            (
                "AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS".to_string(),
                "1".to_string(),
            ),
            ("AIVAULT_DEV_HTTP1_ONLY".to_string(), "1".to_string()),
            (
                "AIVAULT_DEV_CA_CERT_PATH".to_string(),
                self.cert_pem_path.display().to_string(),
            ),
        ]
    }
}

impl Drop for LocalTlsServer {
    fn drop(&mut self) {
        self.handle.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn wait_until_listener_ready(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("local tls listener did not become ready at {}", addr);
}

fn run_aivault_with_env(dir: &TempDir, args: &[&str], envs: &[(String, String)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aivault"));
    command
        .env("AIVAULT_DIR", dir.path())
        .args(rewrite_invoke_to_json(args));
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("failed to run aivault binary")
}

fn rewrite_invoke_to_json<'a>(args: &'a [&'a str]) -> Vec<&'a str> {
    if args.first() == Some(&"invoke") {
        let mut updated = Vec::with_capacity(args.len());
        updated.push("json");
        updated.extend_from_slice(&args[1..]);
        return updated;
    }
    args.to_vec()
}

fn run_ok_json(dir: &TempDir, args: &[&str], envs: &[(String, String)]) -> Value {
    let output = run_aivault_with_env(dir, args, envs);
    assert!(
        output.status.success(),
        "command failed: aivault {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON")
}

fn run_err_text(dir: &TempDir, args: &[&str], envs: &[(String, String)]) -> String {
    let output = run_aivault_with_env(dir, args, envs);
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: aivault {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn e2e_aivaultd_socket_is_required_when_env_is_set() {
    let dir = TempDir::new().expect("temp dir");
    let envs: Vec<(String, String)> = Vec::new();

    // Minimal setup so invoke reaches the daemon connect path.
    let created = run_ok_json(
        &dir,
        &[
            "secrets",
            "create",
            "--name",
            "DAEMON_MISSING_TOKEN",
            "--value",
            "sk-daemon-missing",
            "--scope",
            "global",
        ],
        &envs,
    );
    let secret_id = created["secretId"].as_str().unwrap().to_string();
    let secret_ref = format!("vault:secret:{secret_id}");
    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "missing-cred",
            "--provider",
            "missing-provider",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "header",
            "--host",
            "daemon.test",
        ],
        &envs,
    );
    run_ok_json(
        &dir,
        &[
            "capability",
            "create",
            "missing/echo",
            "--credential",
            "missing-cred",
            "--method",
            "GET",
            "--path",
            "/v1/echo",
        ],
        &envs,
    );

    let missing_sock = dir.path().join("missing.sock");
    let envs = vec![
        (
            "AIVAULTD_SOCKET".to_string(),
            missing_sock.display().to_string(),
        ),
        ("AIVAULTD_AUTOSTART".to_string(), "0".to_string()),
    ];
    let err = run_err_text(
        &dir,
        &["invoke", "missing/echo", "--path", "/v1/echo"],
        &envs,
    );
    assert!(
        err.contains("autostart disabled") || err.contains("failed connecting to aivaultd"),
        "unexpected error output: {}",
        err
    );
}

#[test]
fn e2e_invoke_autostarts_aivaultd_when_not_running() {
    let dir = TempDir::new().expect("temp dir");
    let server = LocalTlsServer::start("daemon.autostart");
    let mut envs = server.env_pairs();

    let created = run_ok_json(
        &dir,
        &[
            "secrets",
            "create",
            "--name",
            "DAEMON_AUTOSTART_TOKEN",
            "--value",
            "sk-daemon-autostart",
            "--scope",
            "global",
        ],
        &envs,
    );
    let secret_id = created["secretId"].as_str().unwrap().to_string();
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "autostart-cred",
            "--provider",
            "autostart-provider",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "header",
            "--host",
            "daemon.autostart",
        ],
        &envs,
    );
    run_ok_json(
        &dir,
        &[
            "capability",
            "create",
            "autostart/echo",
            "--credential",
            "autostart-cred",
            "--method",
            "GET",
            "--path",
            "/v1/echo",
        ],
        &envs,
    );

    let sock_path = dir.path().join("aivaultd.sock");
    envs.push((
        "AIVAULTD_SOCKET".to_string(),
        sock_path.display().to_string(),
    ));
    envs.push(("AIVAULTD_AUTOSTART".to_string(), "1".to_string()));

    // No manual daemon start; the CLI should autostart it and still succeed.
    let out = run_ok_json(
        &dir,
        &["invoke", "autostart/echo", "--path", "/v1/echo"],
        &envs,
    );
    assert_eq!(out["response"]["status"].as_u64(), Some(200));
    assert_eq!(
        out["planned"]["capability"].as_str(),
        Some("autostart/echo")
    );
}

#[test]
fn e2e_invoke_via_aivaultd_unix_socket() {
    let dir = TempDir::new().expect("temp dir");
    let server = LocalTlsServer::start("daemon.test");
    let mut envs = server.env_pairs();

    // Setup vault + broker state via CLI.
    let created = run_ok_json(
        &dir,
        &[
            "secrets",
            "create",
            "--name",
            "DAEMON_TOKEN",
            "--value",
            "sk-daemon",
            "--scope",
            "global",
        ],
        &envs,
    );
    let secret_id = created["secretId"].as_str().unwrap().to_string();
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "daemon-cred",
            "--provider",
            "daemon-provider",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "header",
            "--host",
            "daemon.test",
        ],
        &envs,
    );
    run_ok_json(
        &dir,
        &[
            "capability",
            "create",
            "daemon/echo",
            "--credential",
            "daemon-cred",
            "--method",
            "GET",
            "--path",
            "/v1/echo",
        ],
        &envs,
    );

    let sock_path = dir.path().join("aivaultd.sock");
    let mut daemon_cmd = Command::new(env!("CARGO_BIN_EXE_aivaultd"));
    daemon_cmd.env("AIVAULT_DIR", dir.path());
    for (key, value) in &envs {
        daemon_cmd.env(key, value);
    }
    daemon_cmd
        .arg("--socket")
        .arg(sock_path.to_string_lossy().to_string())
        .arg("--once");
    let mut child = daemon_cmd.spawn().expect("spawn aivaultd");

    // Wait for socket creation.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !sock_path.exists() {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(sock_path.exists(), "daemon socket was not created");

    envs.push((
        "AIVAULTD_SOCKET".to_string(),
        sock_path.display().to_string(),
    ));
    let out = run_ok_json(
        &dir,
        &["invoke", "daemon/echo", "--path", "/v1/echo"],
        &envs,
    );
    assert_eq!(out["response"]["status"].as_u64(), Some(200));
    assert_eq!(out["planned"]["capability"].as_str(), Some("daemon/echo"));

    let status = child.wait().expect("wait daemon");
    assert!(status.success(), "aivaultd did not exit cleanly");
}

#[test]
fn e2e_invoke_falls_back_to_shared_socket_when_autostart_disabled() {
    let dir = TempDir::new().expect("temp dir");
    let server = LocalTlsServer::start("daemon.shared");
    let mut envs = server.env_pairs();

    // Setup vault + broker state via CLI.
    let created = run_ok_json(
        &dir,
        &[
            "secrets",
            "create",
            "--name",
            "DAEMON_SHARED_TOKEN",
            "--value",
            "sk-daemon-shared",
            "--scope",
            "global",
        ],
        &envs,
    );
    let secret_id = created["secretId"].as_str().unwrap().to_string();
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "shared-cred",
            "--provider",
            "shared-provider",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "header",
            "--host",
            "daemon.shared",
        ],
        &envs,
    );
    run_ok_json(
        &dir,
        &[
            "capability",
            "create",
            "shared/echo",
            "--credential",
            "shared-cred",
            "--method",
            "GET",
            "--path",
            "/v1/echo",
        ],
        &envs,
    );

    let shared_sock_dir = dir.path().join("shared").join("run");
    std::fs::create_dir_all(&shared_sock_dir).expect("create shared sock dir");
    let shared_sock_path = shared_sock_dir.join("aivaultd.sock");

    // Start daemon on the "shared" socket override, serve one request.
    let mut daemon_cmd = Command::new(env!("CARGO_BIN_EXE_aivaultd"));
    daemon_cmd.env("AIVAULT_DIR", dir.path());
    for (key, value) in &envs {
        daemon_cmd.env(key, value);
    }
    daemon_cmd.env(
        "AIVAULTD_SHARED_SOCKET",
        shared_sock_path.display().to_string(),
    );
    daemon_cmd
        .arg("--shared")
        .arg("--socket")
        .arg(shared_sock_path.to_string_lossy().to_string())
        .arg("--once");
    let mut child = daemon_cmd.spawn().expect("spawn aivaultd");

    // Wait for socket creation.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !shared_sock_path.exists() {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        shared_sock_path.exists(),
        "shared daemon socket was not created"
    );

    // Autostart disabled: should still succeed by falling back to shared socket.
    envs.push((
        "AIVAULTD_SHARED_SOCKET".to_string(),
        shared_sock_path.display().to_string(),
    ));
    envs.push(("AIVAULTD_AUTOSTART".to_string(), "0".to_string()));
    let out = run_ok_json(&dir, &["invoke", "shared/echo", "--path", "/v1/echo"], &envs);
    assert_eq!(out["response"]["status"].as_u64(), Some(200));
    assert_eq!(out["planned"]["capability"].as_str(), Some("shared/echo"));

    let status = child.wait().expect("wait daemon");
    assert!(status.success(), "aivaultd did not exit cleanly");
}
