#[test]
fn runtime_codex_failure_isolated_from_other_credentials() {
    let _lock = ENV_LOCK.lock().unwrap();
    let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();
    // A permanently unusable account must not prevent a different account or
    // provider from even reaching credential selection.
    vault
        .create_system_secret(
            "CODEX_OAUTH_JSON",
            br#"{"access_token":"old","expires_at":0,"account_id":"broken"}"#,
            SecretScope::Global,
            Vec::new(),
        )
        .unwrap();
    vault
        .create_system_secret(
            "OPENAI_API_KEY",
            b"api-key",
            SecretScope::Global,
            Vec::new(),
        )
        .unwrap();
    let store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
    let envelope = ProxyEnvelope {
        capability: "openai/models".to_string(),
        credential: Some("openai".to_string()),
        request: ProxyEnvelopeRequest {
            method: "GET".to_string(),
            path: "/v1/models".to_string(),
            headers: Vec::new(),
            body: None,
            multipart: None,
            multipart_files: Vec::new(),
            body_file_path: None,
            url: None,
        },
    };
    let (_, planned) = super::plan_capability_envelope(
        &vault,
        &store,
        envelope,
        "127.0.0.1".parse().unwrap(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(planned.credential, "openai");
    assert_eq!(planned.host, "api.openai.com");

    let value = serde_json::to_vec(&serde_json::json!({
        "access_token": "healthy", "refresh_token": "healthy-refresh",
        "account_id": "healthy-account",
        "expires_at": chrono::Utc::now().timestamp_millis() + 7_200_000,
    }))
    .unwrap();
    vault
        .create_system_secret(
            "CODEX_OAUTH_JSON",
            &value,
            SecretScope::Group {
                workspace_id: "moldable".to_string(),
                group_id: "healthy".to_string(),
            },
            Vec::new(),
        )
        .unwrap();
    let (_, planned) = super::plan_capability_envelope(
        &vault,
        &store,
        codex_usage_envelope(Some("openai:codex-oauth-usage:group:moldable:healthy")),
        "127.0.0.1".parse().unwrap(),
        Some("moldable"),
        Some("healthy"),
    )
    .unwrap();
    assert!(planned.headers.iter().any(|h| h.value == "Bearer healthy"));
    // The selected broken account still fails; API keys cannot silently replace it.
    let error = super::plan_capability_envelope(
        &vault,
        &store,
        codex_usage_envelope(None),
        "127.0.0.1".parse().unwrap(),
        None,
        None,
    )
    .unwrap_err();
    assert!(error.contains("missing refresh_token"));
    let mut denied = codex_usage_envelope(None);
    denied.request.method = "POST".to_string();
    let error = super::plan_capability_envelope(
        &vault,
        &store,
        denied,
        "127.0.0.1".parse().unwrap(),
        None,
        None,
    )
    .unwrap_err();
    assert!(error.contains("method not allowed"), "{error}");
}

fn codex_usage_envelope(credential: Option<&str>) -> ProxyEnvelope {
    ProxyEnvelope {
        capability: "openai/codex-usage".to_string(),
        credential: credential.map(str::to_string),
        request: ProxyEnvelopeRequest {
            method: "GET".to_string(),
            path: "/wham/usage".to_string(),
            headers: Vec::new(),
            body: None,
            multipart: None,
            multipart_files: Vec::new(),
            body_file_path: None,
            url: None,
        },
    }
}

#[cfg(debug_assertions)]
fn codex_fixture_secret(vault: &VaultRuntime) -> String {
    let meta = vault.create_system_secret("CODEX_OAUTH_JSON",
        br#"{"access_token":"old","refresh_token":"old-refresh","expires":0,"account_id":"account","email":"test@example.com","plan_type":"pro"}"#,
        SecretScope::Global, Vec::new()).unwrap();
    SecretRef {
        secret_id: meta.secret_id,
    }
    .to_string()
}

#[cfg(debug_assertions)]
fn codex_reply(stream: &mut std::net::TcpStream, status: u16, body: &str) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let n = stream.read(&mut buffer).unwrap();
        assert!(n > 0);
        request.extend_from_slice(&buffer[..n]);
        if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
            let length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            if request.len() >= end + 4 + length {
                break;
            }
        }
    }
    write!(stream, "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
}

#[test]
#[cfg(debug_assertions)]
fn codex_permanent_refresh_failure_is_redacted_and_cached_until_reconnect() {
    let _lock = ENV_LOCK.lock().unwrap();
    let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();
    let secret_ref = codex_fixture_secret(&vault);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _endpoint = ScopedEnvVar::set(
        "AIVAULT_DEV_CODEX_OAUTH_TOKEN_ENDPOINT",
        format!("http://{}/oauth/token", listener.local_addr().unwrap()),
    );
    let _http = ScopedEnvVar::set("AIVAULT_DEV_ALLOW_HTTP_LOCAL", "1");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        codex_reply(
            &mut stream,
            401,
            r#"{"error":{"code":"refresh_token_reused","message":"secret-value-must-not-escape"}}"#,
        );
    });
    let first = crate::codex_oauth::prepare_codex_oauth_access(&vault, &secret_ref).unwrap_err();
    server.join().unwrap();
    assert!(first.contains("refresh_token_reused"));
    assert!(first.contains("Reconnect"));
    assert!(!first.contains("secret-value"));
    // A new runtime proves the failure cache survives daemon/process replacement.
    let other = VaultRuntime::discover();
    other.load().unwrap();
    assert_eq!(
        crate::codex_oauth::prepare_codex_oauth_access(&other, &secret_ref).unwrap_err(),
        first
    );
    let replacement = serde_json::to_vec(&serde_json::json!({
        "access_token":"reconnected", "refresh_token":"new-refresh", "account_id":"account",
        "expires_at":chrono::Utc::now().timestamp_millis() + 7_200_000,
    }))
    .unwrap();
    vault
        .rotate_secret_value(
            &SecretRef::parse(&secret_ref).unwrap().secret_id,
            &replacement,
        )
        .unwrap();
    assert_eq!(
        crate::codex_oauth::prepare_codex_oauth_access(&other, &secret_ref)
            .unwrap()
            .access_token,
        "reconnected"
    );
}

#[test]
#[cfg(debug_assertions)]
fn codex_transient_refresh_can_retry_and_preserves_metadata() {
    let _lock = ENV_LOCK.lock().unwrap();
    let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();
    let secret_ref = codex_fixture_secret(&vault);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _endpoint = ScopedEnvVar::set(
        "AIVAULT_DEV_CODEX_OAUTH_TOKEN_ENDPOINT",
        format!("http://{}/oauth/token", listener.local_addr().unwrap()),
    );
    let _http = ScopedEnvVar::set("AIVAULT_DEV_ALLOW_HTTP_LOCAL", "1");
    let server = thread::spawn(move || {
        for (status, body) in [
            (503, r#"{"error":"temporarily_unavailable"}"#),
            (
                200,
                r#"{"access_token":"fresh","refresh_token":"rotated","expires_in":3600}"#,
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            codex_reply(&mut stream, status, body);
        }
    });
    assert!(
        crate::codex_oauth::prepare_codex_oauth_access(&vault, &secret_ref)
            .unwrap_err()
            .contains("503")
    );
    let access = crate::codex_oauth::prepare_codex_oauth_access(&vault, &secret_ref).unwrap();
    assert_eq!(access.access_token, "fresh");
    assert_eq!(access.email.as_deref(), Some("test@example.com"));
    server.join().unwrap();
    let raw = vault.resolve_secret_ref(&secret_ref, None, None).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(value["plan_type"], "pro");
    assert_eq!(value["refresh_token"], "rotated");
    assert!(value.get("expires").is_none());
    // A stale 401 from the previous access token must adopt the new token.
    let value =
        crate::codex_oauth::prepare_codex_oauth_value(&vault, &secret_ref, Some("old")).unwrap();
    assert_eq!(value["access_token"], "fresh");
}

#[test]
#[cfg(debug_assertions)]
fn codex_refresh_cannot_overwrite_a_concurrent_reconnect() {
    let _lock = ENV_LOCK.lock().unwrap();
    for status in [200, 401] {
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();
        let secret_ref = codex_fixture_secret(&vault);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _endpoint = ScopedEnvVar::set(
            "AIVAULT_DEV_CODEX_OAUTH_TOKEN_ENDPOINT",
            format!("http://{}/oauth/token", listener.local_addr().unwrap()),
        );
        let _http = ScopedEnvVar::set("AIVAULT_DEV_ALLOW_HTTP_LOCAL", "1");
        let writer = vault.clone();
        let secret_id = SecretRef::parse(&secret_ref).unwrap().secret_id;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let replacement = serde_json::to_vec(&serde_json::json!({
                "access_token":"reconnected", "refresh_token":"reconnected-refresh", "account_id":"account",
                "expires_at":chrono::Utc::now().timestamp_millis() + 7_200_000,
            })).unwrap();
            writer
                .rotate_secret_value(&secret_id, &replacement)
                .unwrap();
            codex_reply(
                &mut stream,
                status,
                if status == 200 {
                    r#"{"access_token":"stale-result","refresh_token":"stale-refresh","expires_in":3600}"#
                } else {
                    r#"{"error":{"code":"refresh_token_invalidated"}}"#
                },
            );
        });
        let result = crate::codex_oauth::prepare_codex_oauth_access(&vault, &secret_ref).unwrap();
        assert_eq!(result.access_token, "reconnected");
        server.join().unwrap();
        let current = crate::codex_oauth::prepare_codex_oauth_access(&vault, &secret_ref).unwrap();
        assert_eq!(current.access_token, "reconnected");
    }
}
