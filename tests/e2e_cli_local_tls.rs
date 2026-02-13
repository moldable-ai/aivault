use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Uri};
use axum::routing::any;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;
use serde_json::Value;
use tempfile::TempDir;
use tokio::runtime::Builder as TokioRuntimeBuilder;

#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Clone)]
struct ListenerState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    oauth_issued: Arc<Mutex<u32>>,
}

async fn echo_handler(
    State(state): State<ListenerState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    let mut header_map = HashMap::new();
    for (name, value) in &headers {
        header_map.insert(
            name.as_str().to_ascii_lowercase(),
            value.to_str().unwrap_or_default().to_string(),
        );
    }

    let captured = CapturedRequest {
        method: method.to_string(),
        path: uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string()),
        headers: header_map.clone(),
        body: String::from_utf8_lossy(&body).to_string(),
    };
    state
        .requests
        .lock()
        .expect("lock captured requests")
        .push(captured);

    if uri.path() == "/oauth/token" {
        // Minimal oauth2 token endpoint stub for e2e tests.
        let mut issued = state.oauth_issued.lock().expect("lock oauth counter");
        *issued += 1;
        let token = format!("at-{}", *issued);
        return Json(serde_json::json!({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }));
    }

    Json(serde_json::json!({
        "method": method.as_str(),
        "path": uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"),
        "headers": header_map,
        "body": String::from_utf8_lossy(&body),
    }))
}

struct LocalTlsEchoServer {
    host: String,
    addr: SocketAddr,
    cert_pem_path: PathBuf,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    handle: axum_server::Handle,
    thread: Option<JoinHandle<()>>,
    _cert_dir: TempDir,
}

impl LocalTlsEchoServer {
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

        let requests = Arc::new(Mutex::new(Vec::<CapturedRequest>::new()));
        let state = ListenerState {
            requests: Arc::clone(&requests),
            oauth_issued: Arc::new(Mutex::new(0)),
        };
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
                let app = Router::new()
                    .fallback(any(echo_handler))
                    .with_state(state.clone());
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
            requests,
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

    fn captured_requests(&self) -> Vec<CapturedRequest> {
        self.requests
            .lock()
            .expect("lock captured requests")
            .clone()
    }
}

fn install_rustls_provider_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

impl Drop for LocalTlsEchoServer {
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
    if args.first() == Some(&"capability") && matches!(args.get(1), Some(&"invoke") | Some(&"call"))
    {
        let mut updated = Vec::with_capacity(args.len());
        updated.push("capability");
        updated.push("json");
        updated.extend_from_slice(&args[2..]);
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

fn create_secret(dir: &TempDir, envs: &[(String, String)], name: &str, value: &str) -> String {
    let created = run_ok_json(
        dir,
        &[
            "secrets", "create", "--name", name, "--value", value, "--scope", "global",
        ],
        envs,
    );
    created["secretId"]
        .as_str()
        .expect("secretId should be present")
        .to_string()
}

fn setup_tls_capability(
    dir: &TempDir,
    envs: &[(String, String)],
    upstream_authority: &str,
    capability_id: &str,
    credential_id: &str,
    methods: &[&str],
    paths: &[&str],
) {
    let secret_id = create_secret(
        dir,
        envs,
        &format!(
            "{}_SECRET",
            capability_id.replace('/', "_").to_ascii_uppercase()
        ),
        &format!("sk-{}", capability_id.replace('/', "-")),
    );
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        dir,
        &[
            "credential",
            "create",
            credential_id,
            "--provider",
            "local",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "header",
            "--host",
            upstream_authority,
        ],
        envs,
    );

    let mut args = vec![
        "capability",
        "create",
        capability_id,
        "--credential",
        credential_id,
    ];
    for method in methods {
        args.push("--method");
        args.push(method);
    }
    for path in paths {
        args.push("--path");
        args.push(path);
    }
    run_ok_json(dir, &args, envs);
}

#[test]
fn e2e_local_tls_invoke_routes_to_local_listener_and_injects_secret() {
    let server = LocalTlsEchoServer::start("upstream.test");
    let envs = server.env_pairs();
    let upstream_authority = format!("upstream.test:{}", server.addr.port());

    let dir = TempDir::new().expect("temp dir");
    setup_tls_capability(
        &dir,
        &envs,
        &upstream_authority,
        "local/tls",
        "local-tls-cred",
        &["GET"],
        &["/v1/users"],
    );

    let response = run_ok_json(
        &dir,
        &["invoke", "local/tls", "--path", "/v1/users?x=1"],
        &envs,
    );
    assert_eq!(response["response"]["status"].as_u64(), Some(200));

    let upstream = &response["response"]["json"];
    let authorization = upstream["headers"]["authorization"]
        .as_str()
        .expect("json.headers.authorization should be present");
    assert_eq!(authorization, "Bearer sk-local-tls");

    let captured = server.captured_requests();
    assert!(
        !captured.is_empty(),
        "listener did not capture any requests"
    );
    assert_eq!(captured[0].method, "GET");
    assert_eq!(captured[0].path, "/v1/users?x=1");
    assert_eq!(
        captured[0].headers.get("authorization").map(String::as_str),
        Some("Bearer sk-local-tls")
    );
    assert!(
        captured[0].body.is_empty(),
        "expected empty body for GET request"
    );
}

#[test]
fn e2e_local_tls_rejects_caller_auth_header_before_upstream() {
    let server = LocalTlsEchoServer::start("upstream.test");
    let envs = server.env_pairs();
    let upstream_authority = format!("upstream.test:{}", server.addr.port());

    let dir = TempDir::new().expect("temp dir");
    setup_tls_capability(
        &dir,
        &envs,
        &upstream_authority,
        "local/tls-reject",
        "local-tls-reject-cred",
        &["GET"],
        &["/v1/users"],
    );

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/tls-reject",
            "--path",
            "/v1/users",
            "--header",
            "authorization=Bearer attacker",
        ],
        &envs,
    );
    assert!(
        err.contains("caller-supplied auth headers are not allowed"),
        "unexpected error output: {}",
        err
    );

    let captured = server.captured_requests();
    assert!(
        captured.is_empty(),
        "request should be rejected before reaching upstream listener"
    );
}

#[test]
fn e2e_local_tls_multipart_file_upload_and_content_type_override() {
    let server = LocalTlsEchoServer::start("upstream.test");
    let envs = server.env_pairs();
    let upstream_authority = format!("upstream.test:{}", server.addr.port());
    let dir = TempDir::new().expect("temp dir");

    setup_tls_capability(
        &dir,
        &envs,
        &upstream_authority,
        "local/tls-multipart",
        "local-tls-multipart-cred",
        &["POST"],
        &["/upload"],
    );

    let upload_file = dir.path().join("payload.txt");
    std::fs::write(&upload_file, "hello-local-tls").expect("write upload file");
    let upload_arg = format!("file={}", upload_file.display());

    let response = run_ok_json(
        &dir,
        &[
            "invoke",
            "local/tls-multipart",
            "--method",
            "POST",
            "--path",
            "/upload",
            "--header",
            "content-type=application/json",
            "--multipart-field",
            "mode=test",
            "--multipart-file",
            &upload_arg,
        ],
        &envs,
    );
    assert_eq!(response["response"]["status"].as_u64(), Some(200));

    let captured = server.captured_requests();
    assert_eq!(captured.len(), 1, "expected exactly one captured request");
    let content_type = captured[0]
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        content_type.starts_with("multipart/form-data;"),
        "expected broker-owned multipart content-type, got '{}'",
        content_type
    );
    assert!(
        !content_type.contains("application/json"),
        "caller content-type should have been overridden: '{}'",
        content_type
    );
    assert!(
        captured[0].body.contains("hello-local-tls"),
        "multipart body should include uploaded file content"
    );
}

#[test]
fn e2e_local_tls_response_size_policy_blocks_large_response() {
    let server = LocalTlsEchoServer::start("upstream.test");
    let envs = server.env_pairs();
    let upstream_authority = format!("upstream.test:{}", server.addr.port());
    let dir = TempDir::new().expect("temp dir");

    setup_tls_capability(
        &dir,
        &envs,
        &upstream_authority,
        "local/tls-response-limit",
        "local-tls-response-limit-cred",
        &["GET"],
        &["/v1/users"],
    );

    run_ok_json(
        &dir,
        &[
            "capability",
            "policy",
            "set",
            "--capability",
            "local/tls-response-limit",
            "--max-response-body-bytes",
            "8",
        ],
        &envs,
    );

    let err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/tls-response-limit",
            "--path",
            "/v1/users?x=1",
        ],
        &envs,
    );
    assert!(
        err.contains("response body exceeds capability size limit"),
        "unexpected error output: {}",
        err
    );

    let captured = server.captured_requests();
    assert_eq!(
        captured.len(),
        1,
        "upstream request should still occur before response policy check"
    );
}

#[test]
fn e2e_oauth2_refresh_exchanges_token_writes_back_and_reuses_cache() {
    let server = LocalTlsEchoServer::start("upstream.test");
    let envs = server.env_pairs();
    let upstream_authority = format!("upstream.test:{}", server.addr.port());

    let dir = TempDir::new().expect("temp dir");

    // Secret payload is JSON (stored encrypted in vault) for oauth2 credentials.
    let secret_id = create_secret(
        &dir,
        &envs,
        "OAUTH_SECRET",
        r#"{"clientId":"cid","clientSecret":"csec","refreshToken":"rt","accessToken":null,"accessTokenExpiresAtMs":0}"#,
    );
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "oauth-cred",
            "--provider",
            "oauth",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "oauth2",
            "--grant-type",
            "refresh_token",
            "--token-endpoint",
            &format!("https://{}/oauth/token", upstream_authority),
            "--scope",
            "s1",
            "--host",
            &upstream_authority,
        ],
        &envs,
    );

    run_ok_json(
        &dir,
        &[
            "capability",
            "create",
            "oauth/test",
            "--credential",
            "oauth-cred",
            "--method",
            "GET",
            "--path",
            "/v1/users",
        ],
        &envs,
    );

    let response1 = run_ok_json(
        &dir,
        &["invoke", "oauth/test", "--path", "/v1/users"],
        &envs,
    );
    assert_eq!(response1["response"]["status"].as_u64(), Some(200));
    let upstream1 = &response1["response"]["json"];
    let auth1 = upstream1["headers"]["authorization"]
        .as_str()
        .expect("upstream should receive authorization");
    assert_eq!(auth1, "Bearer at-1");

    let response2 = run_ok_json(
        &dir,
        &["invoke", "oauth/test", "--path", "/v1/users"],
        &envs,
    );
    assert_eq!(response2["response"]["status"].as_u64(), Some(200));
    let upstream2 = &response2["response"]["json"];
    let auth2 = upstream2["headers"]["authorization"]
        .as_str()
        .expect("upstream should receive authorization");
    assert_eq!(auth2, "Bearer at-1");

    let captured = server.captured_requests();
    let token_calls = captured
        .iter()
        .filter(|req| req.path.starts_with("/oauth/token"))
        .count();
    assert_eq!(token_calls, 1, "expected oauth token endpoint called once");
    let token_req = captured
        .iter()
        .find(|req| req.path.starts_with("/oauth/token"))
        .expect("expected captured token endpoint request");
    assert!(
        token_req
            .headers
            .get("authorization")
            .map(|v| v.starts_with("Basic "))
            .unwrap_or(false),
        "expected token endpoint request to use HTTP Basic auth"
    );
    assert!(
        token_req.body.contains("scope=s1"),
        "expected token endpoint request body to include scope"
    );
}

#[test]
fn e2e_oauth2_client_credentials_exchanges_token_writes_back_and_reuses_cache() {
    let server = LocalTlsEchoServer::start("upstream.test");
    let envs = server.env_pairs();
    let upstream_authority = format!("upstream.test:{}", server.addr.port());

    let dir = TempDir::new().expect("temp dir");

    let secret_id = create_secret(
        &dir,
        &envs,
        "OAUTH_CC_SECRET",
        r#"{"clientId":"cid","clientSecret":"csec","refreshToken":"","accessToken":null,"accessTokenExpiresAtMs":0}"#,
    );
    let secret_ref = format!("vault:secret:{secret_id}");

    run_ok_json(
        &dir,
        &[
            "credential",
            "create",
            "oauth-cc-cred",
            "--provider",
            "oauth",
            "--secret-ref",
            &secret_ref,
            "--auth",
            "oauth2",
            "--grant-type",
            "client_credentials",
            "--token-endpoint",
            &format!("https://{}/oauth/token", upstream_authority),
            "--host",
            &upstream_authority,
        ],
        &envs,
    );

    run_ok_json(
        &dir,
        &[
            "capability",
            "create",
            "oauth/cc",
            "--credential",
            "oauth-cc-cred",
            "--method",
            "GET",
            "--path",
            "/v1/users",
        ],
        &envs,
    );

    let response1 = run_ok_json(&dir, &["invoke", "oauth/cc", "--path", "/v1/users"], &envs);
    assert_eq!(response1["response"]["status"].as_u64(), Some(200));
    let upstream1 = &response1["response"]["json"];
    let auth1 = upstream1["headers"]["authorization"]
        .as_str()
        .expect("upstream should receive authorization");
    assert_eq!(auth1, "Bearer at-1");

    let response2 = run_ok_json(&dir, &["invoke", "oauth/cc", "--path", "/v1/users"], &envs);
    assert_eq!(response2["response"]["status"].as_u64(), Some(200));
    let upstream2 = &response2["response"]["json"];
    let auth2 = upstream2["headers"]["authorization"]
        .as_str()
        .expect("upstream should receive authorization");
    assert_eq!(auth2, "Bearer at-1");

    let captured = server.captured_requests();
    let token_calls = captured
        .iter()
        .filter(|req| req.path.starts_with("/oauth/token"))
        .count();
    assert_eq!(token_calls, 1, "expected oauth token endpoint called once");
}

#[test]
fn e2e_local_tls_method_and_path_denials_happen_before_upstream() {
    let server = LocalTlsEchoServer::start("upstream.test");
    let envs = server.env_pairs();
    let upstream_authority = format!("upstream.test:{}", server.addr.port());
    let dir = TempDir::new().expect("temp dir");

    setup_tls_capability(
        &dir,
        &envs,
        &upstream_authority,
        "local/tls-deny",
        "local-tls-deny-cred",
        &["GET"],
        &["/v1/users"],
    );

    let method_err = run_err_text(
        &dir,
        &[
            "invoke",
            "local/tls-deny",
            "--method",
            "POST",
            "--path",
            "/v1/users",
        ],
        &envs,
    );
    assert!(
        method_err.contains("method not allowed by capability"),
        "unexpected method error output: {}",
        method_err
    );

    let path_err = run_err_text(
        &dir,
        &["invoke", "local/tls-deny", "--path", "/v1/private"],
        &envs,
    );
    assert!(
        path_err.contains("path not allowed by capability"),
        "unexpected path error output: {}",
        path_err
    );

    let captured = server.captured_requests();
    assert!(
        captured.is_empty(),
        "denied method/path requests should not reach upstream listener"
    );
}
