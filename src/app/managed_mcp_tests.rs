struct ManagedMcpProviderFixture {
    provider: &'static str,
    secret_name: &'static str,
    secret_alias: &'static str,
    token_endpoint: &'static str,
    hosts: &'static [&'static str],
    capability: &'static str,
    upstream_host: &'static str,
    access_token: &'static str,
}

fn assert_runtime_accepts_pinned_managed_mcp_oauth(fixture: ManagedMcpProviderFixture) {
    let _lock = ENV_LOCK.lock().unwrap();
    let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();
    let oauth = serde_json::to_vec(&serde_json::json!({
        "clientId": format!("{}-client", fixture.provider),
        "refreshToken": format!("{}-refresh", fixture.provider),
        "accessToken": fixture.access_token,
        "accessTokenExpiresAtMs": chrono::Utc::now().timestamp_millis() + 60_000,
    }))
    .unwrap();
    let meta = vault
        .create_system_secret(
            fixture.secret_name,
            &oauth,
            SecretScope::Global,
            vec![fixture.secret_alias.to_string()],
        )
        .unwrap();
    vault
        .pin_secret_to_provider(&meta.secret_id, fixture.provider)
        .unwrap();

    let secret_ref = SecretRef {
        secret_id: meta.secret_id,
    }
    .to_string();
    let mut store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
    store.upsert_credential(StoredCredential {
        id: fixture.provider.to_string(),
        provider: fixture.provider.to_string(),
        workspace_id: None,
        group_id: None,
        auth: AuthStrategy::OAuth2 {
            grant_type: "refresh_token".to_string(),
            token_endpoint: fixture.token_endpoint.to_string(),
            scopes: Vec::new(),
        },
        hosts: fixture
            .hosts
            .iter()
            .map(|host| (*host).to_string())
            .collect(),
        capabilities: vec![fixture.capability.to_string()],
        priority: 0,
        upstream_path_prefix: None,
        secret_ref,
        max_policy_mode: None,
    });

    let mut broker =
        load_runtime_broker_for_context(&vault, &store, Some(fixture.provider), None, None)
            .unwrap();
    let proxy = broker
        .mint_proxy_token(
            &crate::broker::RequestAuth::Operator("moldable-test".to_string()),
            ProxyTokenMintRequest {
                capabilities: vec![fixture.capability.to_string()],
                credential: Some(fixture.provider.to_string()),
                ttl_ms: 60_000,
                context: HashMap::new(),
            },
        )
        .unwrap();
    let planned = broker
        .execute_envelope(
            &crate::broker::RequestAuth::Proxy(proxy.token),
            ProxyEnvelope {
                capability: fixture.capability.to_string(),
                credential: Some(fixture.provider.to_string()),
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/mcp".to_string(),
                    headers: vec![crate::broker::Header {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    }],
                    body: Some(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#.to_string()),
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            "127.0.0.1".parse::<IpAddr>().unwrap(),
        )
        .unwrap();

    assert_eq!(planned.host, fixture.upstream_host);
    assert_eq!(planned.path, "/mcp");
    assert!(planned.headers.iter().any(|header| {
        header.name == "authorization" && header.value == format!("Bearer {}", fixture.access_token)
    }));
}

#[test]
fn runtime_accepts_pinned_granola_oauth_for_compiled_mcp_provider() {
    assert_runtime_accepts_pinned_managed_mcp_oauth(ManagedMcpProviderFixture {
        provider: "granola",
        secret_name: "GRANOLA_OAUTH_JSON",
        secret_alias: "granola.oauth.json",
        token_endpoint: "https://mcp-auth.granola.ai/oauth2/token",
        hosts: &["mcp-auth.granola.ai", "mcp.granola.ai"],
        capability: "granola/mcp",
        upstream_host: "mcp.granola.ai",
        access_token: "granola-access",
    });
}
