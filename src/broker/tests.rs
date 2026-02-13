use super::helpers::*;
use super::*;
use chrono::Utc;

fn operator() -> RequestAuth {
    RequestAuth::Operator("op".to_string())
}

fn loopback_ip() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

fn remote_ip() -> IpAddr {
    "8.8.8.8".parse().unwrap()
}

fn openai_registry() -> Registry {
    Registry::from_templates(vec![ProviderTemplate {
        provider: "openai".to_string(),
        auth: AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
        hosts: vec!["api.openai.com".to_string()],
        capabilities: vec![Capability {
            id: "openai/transcription".to_string(),
            provider: "openai".to_string(),
            allow: AllowPolicy {
                hosts: vec!["api.openai.com".to_string()],
                methods: vec!["POST".to_string()],
                path_prefixes: vec!["/v1/audio/transcriptions".to_string()],
            },
        }],
        vault_secrets: Default::default(),
    }])
    .unwrap()
}

#[test]
fn registry_rejects_duplicate_vault_secret_claims() {
    let t1 = ProviderTemplate {
        provider: "p1".to_string(),
        auth: AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
        hosts: vec!["api.p1.test".to_string()],
        capabilities: Vec::new(),
        vault_secrets: [("DUPLICATE_SECRET".to_string(), "secret".to_string())]
            .into_iter()
            .collect(),
    };
    let t2 = ProviderTemplate {
        provider: "p2".to_string(),
        auth: AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
        hosts: vec!["api.p2.test".to_string()],
        capabilities: Vec::new(),
        vault_secrets: [("DUPLICATE_SECRET".to_string(), "secret".to_string())]
            .into_iter()
            .collect(),
    };

    let err = Registry::from_templates(vec![t1, t2]).unwrap_err();
    assert!(err.message.contains("duplicate vault secret name"));
}

fn base_broker() -> Broker {
    let mut broker = Broker::default_with_registry(Some(openai_registry()));
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "openai".to_string(),
                provider: "openai".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("sk-test".to_string()),
        )
        .unwrap();
    broker
}

fn mint_token(
    broker: &mut Broker,
    capabilities: Vec<&str>,
    credential: Option<&str>,
    ttl_ms: i64,
) -> ProxyToken {
    broker
        .mint_proxy_token(
            &operator(),
            ProxyTokenMintRequest {
                capabilities: capabilities.into_iter().map(|v| v.to_string()).collect(),
                credential: credential.map(|v| v.to_string()),
                ttl_ms,
                context: HashMap::from([(String::from("workspaceId"), String::from("default"))]),
            },
        )
        .unwrap()
}

#[test]
fn story_vault_credential_provider_binding() {
    let mut broker = Broker::default_with_registry(Some(openai_registry()));
    let credential = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "openai-work".to_string(),
                provider: "openai".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("sk".to_string()),
        )
        .unwrap();
    assert_eq!(credential.id, "openai-work");
    assert_eq!(credential.provider, "openai");
}

#[test]
fn story_vault_credential_multi_account_disambiguation() {
    let mut broker = base_broker();
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "openai-personal".to_string(),
                provider: "openai".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("sk-2".to_string()),
        )
        .unwrap();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();

    assert_eq!(planned.credential, "openai");
}

#[test]
fn story_vault_credential_id_uniqueness() {
    let mut broker = base_broker();
    let err = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "openai".to_string(),
                provider: "openai".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("duplicate".to_string()),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

#[test]
fn story_vault_credential_provider_resolution_overrides() {
    let registry = Registry::from_templates(vec![ProviderTemplate {
        provider: "zendesk".to_string(),
        auth: AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
        hosts: vec!["*.zendesk.com".to_string()],
        capabilities: vec![Capability {
            id: "zendesk/tickets".to_string(),
            provider: "zendesk".to_string(),
            allow: AllowPolicy {
                hosts: vec!["*.zendesk.com".to_string()],
                methods: vec!["GET".to_string()],
                path_prefixes: vec!["/api/v2".to_string()],
            },
        }],
        vault_secrets: Default::default(),
    }])
    .unwrap();
    let mut broker = Broker::default_with_registry(Some(registry));
    let credential = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "zendesk-override".to_string(),
                provider: "zendesk".to_string(),
                auth: Some(AuthStrategy::Header {
                    header_name: "x-api-key".to_string(),
                    value_template: "{{secret}}".to_string(),
                }),
                hosts: Some(vec!["acme.zendesk.com".to_string()]),
            },
            SecretMaterial::String("sk-test".to_string()),
        )
        .unwrap();

    assert_eq!(credential.hosts, vec!["acme.zendesk.com"]);
    assert!(matches!(
        credential.auth,
        AuthStrategy::Header { ref header_name, .. } if header_name == "x-api-key"
    ));
}

#[test]
fn story_vault_secret_slot_isolation() {
    let mut broker = base_broker();
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "openai-2".to_string(),
                provider: "openai".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("other".to_string()),
        )
        .unwrap();
    assert_ne!(broker.secrets.get("openai"), broker.secrets.get("openai-2"));
}

#[test]
fn story_vault_host_pattern_core_exact_match() {
    let mut broker = Broker::default_with_registry(None);
    let err = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "wild".to_string(),
                provider: "custom".to_string(),
                auth: Some(AuthStrategy::Header {
                    header_name: "authorization".to_string(),
                    value_template: "Bearer {{secret}}".to_string(),
                }),
                hosts: Some(vec!["*.example.com".to_string()]),
            },
            SecretMaterial::String("x".to_string()),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_vault_per_tenant_host_binding_with_registry() {
    let registry = Registry::from_templates(vec![ProviderTemplate {
        provider: "zendesk".to_string(),
        auth: AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
        hosts: vec!["*.zendesk.com".to_string()],
        capabilities: vec![Capability {
            id: "zendesk/tickets".to_string(),
            provider: "zendesk".to_string(),
            allow: AllowPolicy {
                hosts: vec!["*.zendesk.com".to_string()],
                methods: vec!["GET".to_string()],
                path_prefixes: vec!["/api/v2/tickets".to_string()],
            },
        }],
        vault_secrets: Default::default(),
    }])
    .unwrap();

    let mut broker = Broker::default_with_registry(Some(registry));
    let credential = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "zd-acme".to_string(),
                provider: "zendesk".to_string(),
                auth: None,
                hosts: Some(vec!["acme.zendesk.com".to_string()]),
            },
            SecretMaterial::String("sk".to_string()),
        )
        .unwrap();
    assert_eq!(credential.hosts, vec!["acme.zendesk.com"]);
}

#[test]
fn story_vault_provider_activation_default() {
    let broker = base_broker();
    assert!(broker.capabilities.contains_key("openai/transcription"));
}

#[test]
fn story_cap_provider_binding() {
    let broker = base_broker();
    let cap = broker.capabilities.get("openai/transcription").unwrap();
    assert_eq!(cap.provider, "openai");
}

#[test]
fn story_cap_id_uniqueness_with_overlap() {
    let mut broker = base_broker();
    broker
        .create_capability(
            &operator(),
            Capability {
                id: "openai/chat".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.openai.com".to_string()],
                    methods: vec!["POST".to_string()],
                    path_prefixes: vec!["/v1/chat".to_string()],
                },
            },
        )
        .unwrap();

    let err = broker
        .create_capability(
            &operator(),
            Capability {
                id: "openai/chat".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.openai.com".to_string()],
                    methods: vec!["POST".to_string()],
                    path_prefixes: vec!["/v1/chat/completions".to_string()],
                },
            },
        )
        .unwrap_err();

    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

#[test]
fn story_cap_core_single_upstream_host() {
    let mut broker = base_broker();
    let err = broker
        .create_capability(
            &operator(),
            Capability {
                id: "openai/multi".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["a.example.com".to_string(), "b.example.com".to_string()],
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/v1".to_string()],
                },
            },
        )
        .unwrap_err();

    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_cap_method_and_path_prefix_contract() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "GET".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_cap_user_defined_capabilities() {
    let mut broker = Broker::default_with_registry(None);
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "my-api".to_string(),
                provider: "my-api".to_string(),
                auth: Some(AuthStrategy::Header {
                    header_name: "x-api-key".to_string(),
                    value_template: "{{secret}}".to_string(),
                }),
                hosts: Some(vec!["api.internal.example.com".to_string()]),
            },
            SecretMaterial::String("k".to_string()),
        )
        .unwrap();
    broker
        .create_capability(
            &operator(),
            Capability {
                id: "my-api/users".to_string(),
                provider: "my-api".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.internal.example.com".to_string()],
                    methods: vec!["GET".to_string(), "POST".to_string()],
                    path_prefixes: vec!["/v2/users".to_string()],
                },
            },
        )
        .unwrap();
    assert!(broker.capabilities.contains_key("my-api/users"));
}

#[test]
fn story_env_caller_env_vars_contract() {
    let env = Broker::build_caller_env("http://127.0.0.1:19790", "avp_123");
    assert_eq!(env.aivault_base_url, "http://127.0.0.1:19790");
    assert_eq!(env.aivault_token, "avp_123");
}

#[test]
fn story_env_required_request_fields() {
    let bad = r#"{"request":{"method":"POST","path":"/x"}}"#;
    let err = Broker::parse_envelope(bad).unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

#[test]
fn story_env_reject_unknown_fields() {
    let bad = r#"{"capability":"x","request":{"method":"POST","path":"/x","unexpected":1}}"#;
    let err = Broker::parse_envelope(bad).unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

#[test]
fn story_env_reject_caller_url_field() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: Some("https://evil.com".to_string()),
                },
            },
            loopback_ip(),
        )
        .unwrap_err();

    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_env_single_body_mode_enforcement() {
    let req = ProxyEnvelopeRequest {
        method: "POST".to_string(),
        path: "/x".to_string(),
        headers: Vec::new(),
        body: Some("a".to_string()),
        multipart: Some(HashMap::from([(String::from("k"), String::from("v"))])),
        multipart_files: Vec::new(),
        body_file_path: None,
        url: None,
    };
    let err = resolve_body_mode(&req).unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_env_multipart_content_type_owned_by_broker() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: vec![Header {
                        name: "Content-Type".to_string(),
                        value: "multipart/form-data; boundary=attacker".to_string(),
                    }],
                    body: None,
                    multipart: Some(HashMap::from([(
                        "model".to_string(),
                        "whisper-1".to_string(),
                    )])),
                    multipart_files: vec![MultipartFileSerde {
                        field: "file".to_string(),
                        path: "/tmp/a.wav".to_string(),
                    }],
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();

    let content_type = planned
        .headers
        .iter()
        .find(|h| h.name == "content-type")
        .map(|h| h.value.clone())
        .unwrap();
    assert_eq!(
        content_type,
        "multipart/form-data; boundary=aivault-boundary"
    );
}

#[test]
fn story_env_credential_resolution_order() {
    let mut broker = base_broker();
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "openai-personal".to_string(),
                provider: "openai".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("sk2".to_string()),
        )
        .unwrap();

    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai-personal"),
        60_000,
    );

    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token.clone()),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: Some("openai".to_string()),
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.credential, "openai");

    let token2 = mint_token(&mut broker, vec!["openai/transcription"], None, 60_000);
    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy(token2.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap_err();

    assert_eq!(err.error, ErrorCode::CredentialAmbiguous);
}

#[test]
fn story_env_broker_resolution_chain_e2e() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let envelope = Broker::parse_envelope(
        r#"{
            "capability": "openai/transcription",
            "request": {
                "method": "post",
                "path": "/v1/audio/transcriptions?lang=en",
                "headers": [{"name":"x-trace-id","value":"abc"}]
            }
        }"#,
    )
    .unwrap();

    let planned = broker
        .execute_envelope(&RequestAuth::Proxy(token.token), envelope, loopback_ip())
        .unwrap();

    assert_eq!(planned.capability, "openai/transcription");
    assert_eq!(planned.credential, "openai");
    assert_eq!(planned.host, "api.openai.com");
    assert_eq!(planned.method, "POST");
    assert_eq!(planned.path, "/v1/audio/transcriptions");
    assert!(planned.query.iter().any(|(k, v)| k == "lang" && v == "en"));
    assert!(planned
        .headers
        .iter()
        .any(|h| h.name == "authorization" && h.value == "Bearer sk-test"));

    let audit = broker.audit_records();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].capability, "openai/transcription");
    assert_eq!(audit[0].credential, "openai");
    assert_eq!(audit[0].host, "api.openai.com");
}

#[test]
fn story_env_streaming_response_forwarding() {
    let forwarded = Broker::forward_response(UpstreamResponse {
        status: 200,
        headers: vec![
            Header {
                name: "content-type".to_string(),
                value: "text/event-stream".to_string(),
            },
            Header {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            },
        ],
        body_chunks: vec![b"data: 1\n\n".to_vec(), b"data: 2\n\n".to_vec()],
    });

    assert_eq!(forwarded.status, 200);
    assert_eq!(forwarded.body_chunks.len(), 2);
    assert_eq!(forwarded.headers.len(), 1);
    assert_eq!(forwarded.headers[0].name, "content-type");
}

#[test]
fn story_transport_envelope_upstream_derived_from_policy() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.host, "api.openai.com");
    assert_eq!(planned.scheme, "https");
}

#[test]
fn story_transport_passthrough_base_url_swap() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let planned = broker
        .execute_passthrough(
            &RequestAuth::Proxy(token.token),
            "POST",
            "/v/openai/v1/audio/transcriptions",
            Vec::new(),
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.planned.path, "/v1/audio/transcriptions");
}

#[test]
fn story_transport_passthrough_capability_inference() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let planned = broker
        .execute_passthrough(
            &RequestAuth::Proxy(token.token),
            "POST",
            "/v/openai/v1/audio/transcriptions",
            Vec::new(),
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.audit_capability, "openai/transcription");
}

#[test]
fn story_transport_passthrough_token_scope_evaluation() {
    let mut broker = base_broker();
    let token = mint_token(&mut broker, vec![], Some("openai"), 60_000);
    let err = broker
        .execute_passthrough(
            &RequestAuth::Proxy(token.token),
            "POST",
            "/v/openai/v1/audio/transcriptions",
            Vec::new(),
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::CapabilityNotFound);
}

#[test]
fn story_transport_passthrough_host_derived_from_capability() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let planned = broker
        .execute_passthrough(
            &RequestAuth::Proxy(token.token),
            "POST",
            "/v/openai/v1/audio/transcriptions",
            vec![Header {
                name: "Host".to_string(),
                value: "evil.com".to_string(),
            }],
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.planned.host, "api.openai.com");
    assert!(planned.planned.headers.iter().all(|h| h.name != "host"));
}

#[test]
fn story_transport_passthrough_credential_segment_extraction() {
    let parsed = parse_passthrough_path("/v/openai/v1/audio/transcriptions").unwrap();
    assert_eq!(parsed, ("openai", "/v1/audio/transcriptions"));

    let err = parse_passthrough_path("/v//v1/audio/transcriptions").unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);

    let err = parse_passthrough_path("/v/openai").unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

#[test]
fn story_transport_websocket_connect_frame() {
    let mut broker = base_broker();
    broker
        .upsert_capability(
            &operator(),
            Capability {
                id: "deepgram/realtime".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.openai.com".to_string()],
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/v1/audio/transcriptions".to_string()],
                },
            },
        )
        .unwrap();
    let token = mint_token(
        &mut broker,
        vec!["deepgram/realtime"],
        Some("openai"),
        60_000,
    );

    let planned = broker
        .execute_ws_connect(
            &RequestAuth::Proxy(token.token),
            WsConnectFrame {
                capability: "deepgram/realtime".to_string(),
                path: "/v1/audio/transcriptions".to_string(),
                target_url: None,
            },
            loopback_ip(),
        )
        .unwrap();

    assert_eq!(planned.method, "GET");
    assert_eq!(planned.scheme, "wss");
}

#[test]
fn story_transport_websocket_upstream_derived_from_capability() {
    let mut broker = base_broker();
    broker
        .upsert_capability(
            &operator(),
            Capability {
                id: "openai/realtime".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.openai.com".to_string()],
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/v1/realtime".to_string()],
                },
            },
        )
        .unwrap();
    let token = mint_token(&mut broker, vec!["openai/realtime"], Some("openai"), 60_000);

    let planned = broker
        .execute_ws_connect(
            &RequestAuth::Proxy(token.token),
            WsConnectFrame {
                capability: "openai/realtime".to_string(),
                path: "/v1/realtime/sessions".to_string(),
                target_url: None,
            },
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.host, "api.openai.com");
    assert_eq!(planned.scheme, "wss");
}

#[test]
fn story_transport_websocket_upgrade_method_enforced_as_get() {
    let mut broker = base_broker();
    broker
        .upsert_capability(
            &operator(),
            Capability {
                id: "openai/ws-post-only".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.openai.com".to_string()],
                    methods: vec!["POST".to_string()],
                    path_prefixes: vec!["/v1/realtime".to_string()],
                },
            },
        )
        .unwrap();
    let token = mint_token(
        &mut broker,
        vec!["openai/ws-post-only"],
        Some("openai"),
        60_000,
    );

    let err = broker
        .execute_ws_connect(
            &RequestAuth::Proxy(token.token),
            WsConnectFrame {
                capability: "openai/ws-post-only".to_string(),
                path: "/v1/realtime/sessions".to_string(),
                target_url: None,
            },
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_transport_websocket_reject_target_url() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let err = broker
        .execute_ws_connect(
            &RequestAuth::Proxy(token.token),
            WsConnectFrame {
                capability: "openai/transcription".to_string(),
                path: "/v1/audio/transcriptions".to_string(),
                target_url: Some("wss://evil.com".to_string()),
            },
            loopback_ip(),
        )
        .unwrap_err();

    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_transport_structured_broker_errors() {
    let err = BrokerError::new(
        ErrorCode::PolicyViolation,
        "Host 'evil.com' not allowed for capability 'openai/transcription'",
    );
    assert_eq!(err.error, ErrorCode::PolicyViolation);
    assert!(err.message.contains("Host 'evil.com'"));
}

#[test]
fn story_transport_error_code_enumeration() {
    let expected = vec![
        "policy_violation",
        "capability_not_found",
        "credential_not_found",
        "credential_ambiguous",
        "vault_unavailable",
        "auth_failed",
        "upstream_unreachable",
        "token_invalid",
    ];
    let actual = vec![
        ErrorCode::PolicyViolation,
        ErrorCode::CapabilityNotFound,
        ErrorCode::CredentialNotFound,
        ErrorCode::CredentialAmbiguous,
        ErrorCode::VaultUnavailable,
        ErrorCode::AuthFailed,
        ErrorCode::UpstreamUnreachable,
        ErrorCode::TokenInvalid,
    ]
    .into_iter()
    .map(|code| serde_json::to_string(&code).unwrap().replace('"', ""))
    .collect::<Vec<_>>();

    assert_eq!(actual, expected);
}

#[test]
fn story_transport_response_header_filtering() {
    let forwarded = Broker::forward_response(UpstreamResponse {
        status: 200,
        headers: vec![
            Header {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            Header {
                name: "x-trace-id".to_string(),
                value: "abc".to_string(),
            },
            Header {
                name: "connection".to_string(),
                value: "keep-alive".to_string(),
            },
            Header {
                name: "transfer-encoding".to_string(),
                value: "chunked".to_string(),
            },
            Header {
                name: "content-length".to_string(),
                value: "42".to_string(),
            },
            Header {
                name: "sec-websocket-accept".to_string(),
                value: "xyz".to_string(),
            },
        ],
        body_chunks: vec![b"{}".to_vec()],
    });

    assert_eq!(forwarded.status, 200);
    assert_eq!(forwarded.headers.len(), 2);
    assert!(forwarded.headers.iter().any(|h| h.name == "content-type"));
    assert!(forwarded.headers.iter().any(|h| h.name == "x-trace-id"));
}

#[test]
fn story_token_operator_and_proxy_class_separation() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let err = broker
        .create_operator_secret(&RequestAuth::Proxy(token.token), "x", "y")
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::OperatorAuthRequired);
}

#[test]
fn story_token_proxy_scope_capability_and_credential() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    assert_eq!(token.capabilities, vec!["openai/transcription"]);
    assert_eq!(token.credential.as_deref(), Some("openai"));
}

#[test]
fn story_token_proxy_ttl_and_context() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        10,
    );
    assert!(token.expires_at_ms > Utc::now().timestamp_millis());
    assert_eq!(
        token.context.get("workspaceId"),
        Some(&"default".to_string())
    );
}

#[test]
fn story_token_opaque_server_side_validation() {
    let mut broker = base_broker();
    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy("avp_not_minted_here".to_string()),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::TokenInvalid);
}

#[test]
fn story_token_credential_pin_auto_resolution() {
    let mut broker = base_broker();
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "openai-personal".to_string(),
                provider: "openai".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("sk-personal".to_string()),
        )
        .unwrap();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai-personal"),
        60_000,
    );

    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.credential, "openai-personal");
}

#[test]
fn story_token_proxy_broker_endpoints_only() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let err = broker
        .list_operator_secrets(&RequestAuth::Proxy(token.token))
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::OperatorAuthRequired);
}

#[test]
fn story_token_mint_proxy_endpoint() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    assert!(token.token.starts_with("avp_"));
}

#[test]
fn story_token_mint_validates_capability_provider_compatibility() {
    let mut broker = base_broker();
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "other".to_string(),
                provider: "other".to_string(),
                auth: Some(AuthStrategy::Header {
                    header_name: "authorization".to_string(),
                    value_template: "Bearer {{secret}}".to_string(),
                }),
                hosts: Some(vec!["api.other.com".to_string()]),
            },
            SecretMaterial::String("x".to_string()),
        )
        .unwrap();

    let err = broker
        .mint_proxy_token(
            &operator(),
            ProxyTokenMintRequest {
                capabilities: vec!["openai/transcription".to_string()],
                credential: Some("other".to_string()),
                ttl_ms: 60_000,
                context: HashMap::new(),
            },
        )
        .unwrap_err();

    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_token_localhost_default_enforcement() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            remote_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_token_operator_crud_surface() {
    let mut broker = base_broker();
    broker
        .create_operator_secret(&operator(), "gateway.token", "abc")
        .unwrap();
    let secrets = broker.list_operator_secrets(&operator()).unwrap();
    assert_eq!(secrets.len(), 1);
}

#[test]
fn story_token_operator_secret_crud_isolated_from_proxy() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let err = broker
        .create_operator_secret(&RequestAuth::Proxy(token.token), "x", "y")
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::OperatorAuthRequired);
}

#[test]
fn story_auth_header_injection() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
        Some(&SecretMaterial::String("sk-test".to_string())),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "GET",
    )
    .unwrap();
    assert_eq!(headers[0].value, "Bearer sk-test");
}

#[test]
fn story_auth_query_injection() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::Query {
            param_name: "api_key".to_string(),
        },
        Some(&SecretMaterial::String("k".to_string())),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "GET",
    )
    .unwrap();
    assert_eq!(query, vec![("api_key".to_string(), "k".to_string())]);
}

#[test]
fn story_auth_basic_injection() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::Basic,
        Some(&SecretMaterial::Basic {
            username: "u".to_string(),
            password: "p".to_string(),
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "GET",
    )
    .unwrap();
    assert!(headers[0].value.starts_with("Basic "));
}

#[test]
fn story_auth_token_in_path_injection() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/sendMessage".to_string();
    apply_auth(
        &AuthStrategy::Path {
            prefix_template: "/bot{{secret}}".to_string(),
        },
        Some(&SecretMaterial::String("123:abc".to_string())),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap();
    assert_eq!(path, "/bot123:abc/sendMessage");
    assert!(headers.is_empty());
    assert!(query.is_empty());

    // Fail-closed if the caller tries to supply the broker-managed prefix directly.
    let mut path = "/botattacker/sendMessage".to_string();
    let err = apply_auth(
        &AuthStrategy::Path {
            prefix_template: "/bot{{secret}}".to_string(),
        },
        Some(&SecretMaterial::String("123:abc".to_string())),
        &mut Vec::new(),
        &mut Vec::new(),
        &mut path,
        true,
        "POST",
    )
    .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_auth_multi_header_injection() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::MultiHeader(vec![
            AuthHeaderTemplate {
                header_name: "x-dd-api-key".to_string(),
                value_template: "{{api_key}}".to_string(),
            },
            AuthHeaderTemplate {
                header_name: "x-dd-app-key".to_string(),
                value_template: "{{app_key}}".to_string(),
            },
        ]),
        Some(&SecretMaterial::Fields(HashMap::from([
            ("api_key".to_string(), "k1".to_string()),
            ("app_key".to_string(), "k2".to_string()),
        ]))),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "GET",
    )
    .unwrap();

    assert_eq!(headers.len(), 2);
    assert!(headers
        .iter()
        .any(|h| h.name == "x-dd-api-key" && h.value == "k1"));
    assert!(headers
        .iter()
        .any(|h| h.name == "x-dd-app-key" && h.value == "k2"));

    // Caller-supplied managed headers are rejected.
    let err = sanitize_headers(
        &[Header {
            name: "x-dd-api-key".to_string(),
            value: "attacker".to_string(),
        }],
        &AuthStrategy::MultiHeader(vec![AuthHeaderTemplate {
            header_name: "x-dd-api-key".to_string(),
            value_template: "{{api_key}}".to_string(),
        }]),
    )
    .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_auth_oauth2_refresh_and_cache() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    let err = apply_auth(
        &AuthStrategy::OAuth2 {
            grant_type: "refresh_token".to_string(),
            token_endpoint: "https://oauth.example/token".to_string(),
            scopes: vec!["scope:a".to_string()],
        },
        Some(&SecretMaterial::OAuth2 {
            client_id: "cid".to_string(),
            client_secret: "csec".to_string(),
            refresh_token: "rt".to_string(),
            access_token: None,
            access_token_expires_at_ms: None,
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap_err();
    assert_eq!(err.error, ErrorCode::OauthRefreshRequired);
}

#[test]
fn story_auth_oauth2_client_credentials_grant() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/oauth/token".to_string();
    let err = apply_auth(
        &AuthStrategy::OAuth2 {
            grant_type: "client_credentials".to_string(),
            token_endpoint: "https://oauth.example/token".to_string(),
            scopes: Vec::new(),
        },
        Some(&SecretMaterial::OAuth2 {
            client_id: "cid".to_string(),
            client_secret: "csec".to_string(),
            refresh_token: String::new(),
            access_token: None,
            access_token_expires_at_ms: None,
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap_err();
    assert_eq!(err.error, ErrorCode::OauthRefreshRequired);
}

#[test]
fn story_auth_oauth2_scopes_applied() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/oauth/token".to_string();
    let err = apply_auth(
        &AuthStrategy::OAuth2 {
            grant_type: "client_credentials".to_string(),
            token_endpoint: "https://oauth.example/token".to_string(),
            scopes: vec!["scope:a".to_string(), "scope:b".to_string()],
        },
        Some(&SecretMaterial::OAuth2 {
            client_id: "cid".to_string(),
            client_secret: "csec".to_string(),
            refresh_token: String::new(),
            access_token: None,
            access_token_expires_at_ms: None,
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap_err();
    assert_eq!(err.error, ErrorCode::OauthRefreshRequired);
}

#[test]
fn story_auth_oauth2_consent_outside_broker() {
    let mut broker = Broker::default_with_registry(None);
    let err = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "oauth-bad".to_string(),
                provider: "google".to_string(),
                auth: Some(AuthStrategy::OAuth2 {
                    grant_type: "authorization_code".to_string(),
                    token_endpoint: "https://oauth.example/token".to_string(),
                    scopes: vec!["scope-a".to_string()],
                }),
                hosts: Some(vec!["api.google.com".to_string()]),
            },
            SecretMaterial::OAuth2 {
                client_id: "cid".to_string(),
                client_secret: "csecret".to_string(),
                refresh_token: "rtok".to_string(),
                access_token: None,
                access_token_expires_at_ms: None,
            },
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
    assert!(err.message.contains("outside broker"));
}

#[test]
fn story_auth_aws_sigv4_signing() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::AwsSigV4 {
            service: "s3".to_string(),
            region: "us-east-1".to_string(),
        },
        Some(&SecretMaterial::Aws {
            access_key_id: "akid".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap();
    assert!(headers[0]
        .value
        .contains("AWS4-HMAC-SHA256 Credential=akid"));
}

#[test]
fn story_auth_aws_session_token_optional() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::AwsSigV4 {
            service: "s3".to_string(),
            region: "us-east-1".to_string(),
        },
        Some(&SecretMaterial::Aws {
            access_key_id: "akid".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: Some("sts-token".to_string()),
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap();
    assert!(headers[0].value.contains("SessionToken=sts-token"));
}

#[test]
fn story_auth_hmac_signing() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::Hmac {
            algorithm: "sha256".to_string(),
            header_name: "x-signature".to_string(),
            value_template: "sha256={{signature}}".to_string(),
        },
        Some(&SecretMaterial::Hmac {
            secret: "sec".to_string(),
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap();
    assert!(headers[0].value.contains("sha256=sha256:sec:POST\n/x\n"));
}

#[test]
fn story_auth_hmac_canonical_signature_input() {
    let mut headers = Vec::new();
    let mut query = vec![
        ("b".to_string(), "2".to_string()),
        ("a".to_string(), "1".to_string()),
    ];
    let mut path = "/v1/messages".to_string();
    apply_auth(
        &AuthStrategy::Hmac {
            algorithm: "sha256".to_string(),
            header_name: "x-signature".to_string(),
            value_template: "sha256={{signature}}".to_string(),
        },
        Some(&SecretMaterial::Hmac {
            secret: "sec".to_string(),
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap();
    assert!(headers[0]
        .value
        .contains("sha256:sec:POST\n/v1/messages\na=1&b=2"));
}

#[test]
fn story_auth_mtls_client_cert() {
    let mut headers = Vec::new();
    let mut query = Vec::new();
    let mut path = "/x".to_string();
    apply_auth(
        &AuthStrategy::Mtls,
        Some(&SecretMaterial::Mtls {
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
        }),
        &mut headers,
        &mut query,
        &mut path,
        true,
        "POST",
    )
    .unwrap();
    assert_eq!(headers[0].name, "x-client-cert-sha");
}

#[test]
fn story_auth_unknown_type_fails_closed() {
    let err = Broker::parse_auth_type("custom-x").unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_reg_optional_conformance() {
    let mut broker = Broker::default_with_registry(None);
    let credential = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "custom".to_string(),
                provider: "custom".to_string(),
                auth: Some(AuthStrategy::Header {
                    header_name: "authorization".to_string(),
                    value_template: "Bearer {{secret}}".to_string(),
                }),
                hosts: Some(vec!["api.custom.example".to_string()]),
            },
            SecretMaterial::String("k".to_string()),
        )
        .unwrap();
    assert_eq!(credential.provider, "custom");
}

#[test]
fn story_reg_provider_based_capability_activation() {
    let broker = base_broker();
    assert!(broker.capabilities.contains_key("openai/transcription"));
}

#[test]
fn story_reg_capability_shape_without_credential_field() {
    let reg = openai_registry();
    let provider = reg.provider("openai").unwrap();
    let cap = &provider.capabilities[0];
    assert_eq!(cap.provider, "openai");
}

#[test]
fn story_reg_runtime_immutability() {
    let reg = openai_registry();
    let providers = reg.providers();
    assert_eq!(providers.len(), 1);
    // Returned providers are cloned; mutating them does not alter registry internals.
    let mut changed = providers;
    changed[0].hosts.push("evil.com".to_string());
    let reloaded = reg.provider("openai").unwrap();
    assert_eq!(reloaded.hosts, vec!["api.openai.com"]);
}

#[test]
fn story_reg_no_secret_material_in_registry() {
    let reg = openai_registry();
    let provider = reg.provider("openai").unwrap();
    assert_eq!(provider.hosts, vec!["api.openai.com"]);
}

#[test]
fn story_reg_custom_provider_explicit_auth_hosts() {
    let mut broker = Broker::default_with_registry(None);
    let err = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "bad".to_string(),
                provider: "custom".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("x".to_string()),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::InvalidRequest);
}

#[test]
fn story_reg_custom_capabilities_same_schema() {
    let mut broker = Broker::default_with_registry(None);
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "api".to_string(),
                provider: "api".to_string(),
                auth: Some(AuthStrategy::Query {
                    param_name: "api_key".to_string(),
                }),
                hosts: Some(vec!["api.example.com".to_string()]),
            },
            SecretMaterial::String("k".to_string()),
        )
        .unwrap();
    broker
        .create_capability(
            &operator(),
            Capability {
                id: "api/users".to_string(),
                provider: "api".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.example.com".to_string()],
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/v2/users".to_string()],
                },
            },
        )
        .unwrap();
    assert!(broker.capabilities.contains_key("api/users"));
}

#[test]
fn story_reg_json_only_provider_extensibility() {
    let registry = Registry::from_json_str(
        r#"{
            "providers": [
                {
                    "provider": "example",
                    "auth": {
                        "header": {
                            "header_name": "authorization",
                            "value_template": "Bearer {{secret}}"
                        }
                    },
                    "hosts": ["api.example.com"],
                    "capabilities": [
                        {
                            "id": "example/list",
                            "provider": "example",
                            "allow": {
                                "hosts": ["api.example.com"],
                                "methods": ["GET"],
                                "pathPrefixes": ["/v1/items"]
                            }
                        }
                    ]
                }
            ]
        }"#,
    )
    .unwrap();

    let mut broker = Broker::default_with_registry(Some(registry));
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "example-main".to_string(),
                provider: "example".to_string(),
                auth: None,
                hosts: None,
            },
            SecretMaterial::String("sk-example".to_string()),
        )
        .unwrap();

    let token = mint_token(
        &mut broker,
        vec!["example/list"],
        Some("example-main"),
        60_000,
    );
    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "example/list".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "GET".to_string(),
                    path: "/v1/items".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.host, "api.example.com");
}

#[test]
fn story_sec_fail_closed_empty_policy_inputs() {
    let mut broker = base_broker();
    let err = broker
        .create_capability(
            &operator(),
            Capability {
                id: "bad".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec![],
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/".to_string()],
                },
            },
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_sec_path_prefix_root_explicit_allow_all() {
    let mut broker = base_broker();
    broker
        .create_capability(
            &operator(),
            Capability {
                id: "openai/all-paths".to_string(),
                provider: "openai".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.openai.com".to_string()],
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/".to_string()],
                },
            },
        )
        .unwrap();
    let token = mint_token(
        &mut broker,
        vec!["openai/all-paths"],
        Some("openai"),
        60_000,
    );

    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/all-paths".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "GET".to_string(),
                    path: "/v1/anything".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.path, "/v1/anything");
}

#[test]
fn story_sec_path_normalization_traversal_rejection() {
    let err = normalize_path_and_query("/v1/../etc/passwd").unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_sec_scheme_port_ssrf_guards() {
    let broker = base_broker();
    let err = broker
        .enforce_upstream_target_rules("https", "169.254.169.254", None)
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);

    let err = broker
        .enforce_upstream_target_rules("https", "api.openai.com", Some(8443))
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_sec_redirect_auth_exfiltration_guard() {
    let blocked = Broker::new(BrokerConfig::default(), None);
    let err = blocked
        .validate_redirect_hop("api.openai.com", "evil.com")
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);

    let cfg = BrokerConfig {
        redirect_mode: RedirectMode::Revalidate,
        ..BrokerConfig::default()
    };
    let allowed = Broker::new(cfg, None)
        .validate_redirect_hop("api.openai.com", "evil.com")
        .unwrap();
    assert!(allowed);
}

#[test]
fn story_sec_reserved_and_auth_class_header_controls() {
    let headers = vec![Header {
        name: "Authorization".to_string(),
        value: "Bearer attacker".to_string(),
    }];
    let err = sanitize_headers(
        &headers,
        &AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_sec_reserved_header_normative_minimum() {
    let headers = vec![
        Header {
            name: "Host".to_string(),
            value: "evil.com".to_string(),
        },
        Header {
            name: "Connection".to_string(),
            value: "keep-alive".to_string(),
        },
        Header {
            name: "Keep-Alive".to_string(),
            value: "timeout=5".to_string(),
        },
        Header {
            name: "TE".to_string(),
            value: "trailers".to_string(),
        },
        Header {
            name: "Trailer".to_string(),
            value: "x-trace".to_string(),
        },
        Header {
            name: "Transfer-Encoding".to_string(),
            value: "chunked".to_string(),
        },
        Header {
            name: "Upgrade".to_string(),
            value: "websocket".to_string(),
        },
        Header {
            name: "Content-Length".to_string(),
            value: "1".to_string(),
        },
        Header {
            name: "Sec-WebSocket-Key".to_string(),
            value: "abc".to_string(),
        },
        Header {
            name: "X-Ok".to_string(),
            value: "1".to_string(),
        },
    ];
    let sanitized = sanitize_headers(
        &headers,
        &AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
    )
    .unwrap();
    assert_eq!(sanitized.len(), 1);
    assert_eq!(sanitized[0].name, "x-ok");

    for auth_name in ["authorization", "proxy-authorization"] {
        let err = sanitize_headers(
            &[Header {
                name: auth_name.to_string(),
                value: "x".to_string(),
            }],
            &AuthStrategy::Header {
                header_name: "authorization".to_string(),
                value_template: "Bearer {{secret}}".to_string(),
            },
        )
        .unwrap_err();
        assert_eq!(err.error, ErrorCode::PolicyViolation);
    }
}

#[test]
fn story_sec_host_matching_rules() {
    assert!(host_matches("api.openai.com", "api.openai.com"));
    assert!(!host_matches("api.openai.com", "api.openai.com.exfil.io"));
    assert!(host_matches("*.openai.com", "api.openai.com"));
    assert!(!host_matches("*.openai.com", "openai.com"));
}

#[test]
fn story_sec_host_wildcard_dot_boundary_rules() {
    assert!(!host_matches("*.example.com", "badexample.com"));
    assert!(!host_matches("*.example.com", "example.com"));
    assert!(host_matches(
        "*.xn--bcher-kva.example",
        "shop.xn--bcher-kva.example"
    ));
}

#[test]
fn story_sec_host_punycode_normalization() {
    assert!(host_matches(
        "XN--BCHER-KVA.EXAMPLE",
        "xn--bcher-kva.example"
    ));
    let normalized = normalize_hosts(vec![
        "XN--BCHER-KVA.EXAMPLE".to_string(),
        "xn--bcher-kva.example".to_string(),
    ])
    .unwrap();
    assert_eq!(normalized, vec!["xn--bcher-kva.example".to_string()]);
}

#[test]
fn story_sec_query_auth_param_owned_by_broker() {
    let mut headers = Vec::new();
    let mut query = vec![("api_key".to_string(), "attacker".to_string())];
    let mut path = "/v1/x".to_string();
    apply_auth(
        &AuthStrategy::Query {
            param_name: "api_key".to_string(),
        },
        Some(&SecretMaterial::String("safe".to_string())),
        &mut headers,
        &mut query,
        &mut path,
        false,
        "GET",
    )
    .unwrap();
    assert_eq!(query, vec![("api_key".to_string(), "safe".to_string())]);
}

#[test]
fn story_sec_effective_host_intersection_fail_closed() {
    let mut broker = Broker::default_with_registry(None);
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "custom".to_string(),
                provider: "custom".to_string(),
                auth: Some(AuthStrategy::Header {
                    header_name: "x-api-key".to_string(),
                    value_template: "{{secret}}".to_string(),
                }),
                hosts: Some(vec!["api.allowed.example".to_string()]),
            },
            SecretMaterial::String("k".to_string()),
        )
        .unwrap();
    broker
        .create_capability(
            &operator(),
            Capability {
                id: "custom/read".to_string(),
                provider: "custom".to_string(),
                allow: AllowPolicy {
                    hosts: vec!["api.denied.example".to_string()],
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/v1".to_string()],
                },
            },
        )
        .unwrap();
    let token = mint_token(&mut broker, vec!["custom/read"], Some("custom"), 60_000);
    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "custom/read".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "GET".to_string(),
                    path: "/v1/items".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
    assert!(err.message.contains("effective host intersection is empty"));
}

#[test]
fn story_reg_host_pattern_matching() {
    let registry = Registry::from_templates(vec![ProviderTemplate {
        provider: "zendesk".to_string(),
        auth: AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        },
        hosts: vec!["*.zendesk.com".to_string()],
        capabilities: vec![Capability {
            id: "zendesk/tickets".to_string(),
            provider: "zendesk".to_string(),
            allow: AllowPolicy {
                hosts: vec!["*.zendesk.com".to_string()],
                methods: vec!["GET".to_string()],
                path_prefixes: vec!["/api/v2/tickets".to_string()],
            },
        }],
        vault_secrets: Default::default(),
    }])
    .unwrap();

    let mut broker = Broker::default_with_registry(Some(registry));
    broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "zd-acme".to_string(),
                provider: "zendesk".to_string(),
                auth: None,
                hosts: Some(vec!["acme.zendesk.com".to_string()]),
            },
            SecretMaterial::String("sk-zd".to_string()),
        )
        .unwrap();

    let token = mint_token(
        &mut broker,
        vec!["zendesk/tickets"],
        Some("zd-acme"),
        60_000,
    );
    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "zendesk/tickets".to_string(),
                credential: Some("zd-acme".to_string()),
                request: ProxyEnvelopeRequest {
                    method: "GET".to_string(),
                    path: "/api/v2/tickets/1".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.host, "acme.zendesk.com");
}

#[test]
fn story_reg_per_tenant_host_binding() {
    let registry = Registry::from_templates(vec![ProviderTemplate {
        provider: "shopify".to_string(),
        auth: AuthStrategy::Header {
            header_name: "x-shopify-access-token".to_string(),
            value_template: "{{secret}}".to_string(),
        },
        hosts: vec!["*.myshopify.com".to_string()],
        capabilities: vec![Capability {
            id: "shopify/orders".to_string(),
            provider: "shopify".to_string(),
            allow: AllowPolicy {
                hosts: vec!["*.myshopify.com".to_string()],
                methods: vec!["GET".to_string()],
                path_prefixes: vec!["/admin/api".to_string()],
            },
        }],
        vault_secrets: Default::default(),
    }])
    .unwrap();

    let mut broker = Broker::default_with_registry(Some(registry));
    let err = broker
        .create_credential(
            &operator(),
            CredentialInput {
                id: "shop-bad".to_string(),
                provider: "shopify".to_string(),
                auth: None,
                hosts: Some(vec!["evil.com".to_string()]),
            },
            SecretMaterial::String("sk".to_string()),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
}

#[test]
fn story_sec_body_file_path_host_constrained_egress() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    let planned = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: Some("/tmp/id_rsa".to_string()),
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();

    assert_eq!(planned.host, "api.openai.com");
    assert!(matches!(
        planned.body_mode,
        RequestBodyMode::BodyFilePath(ref path) if path == "/tmp/id_rsa"
    ));
}

#[test]
fn story_sec_broker_call_audit_records() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();

    let audit = broker.audit_records();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].capability, "openai/transcription");
    assert_eq!(audit[0].credential, "openai");
    assert_eq!(audit[0].host, "api.openai.com");
}

#[test]
fn story_sec_stolen_proxy_token_limited_by_scope_and_ttl() {
    let mut broker = base_broker();
    let token = mint_token(&mut broker, vec!["openai/transcription"], Some("openai"), 1);
    std::thread::sleep(std::time::Duration::from_millis(5));
    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::TokenInvalid);
}

#[test]
fn story_adv_capability_rate_and_size_limits() {
    let mut broker = base_broker();
    broker
        .set_capability_advanced_policy(
            &operator(),
            "openai/transcription",
            CapabilityAdvancedPolicy {
                rate_limit_per_minute: Some(1),
                max_request_body_bytes: Some(4),
                max_response_body_bytes: None,
                response_body_blocklist: Vec::new(),
            },
        )
        .unwrap();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );

    broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token.clone()),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: Some("1234".to_string()),
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap();

    let err = broker
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: Some("1234".to_string()),
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
    assert!(err.message.contains("rate limit"));

    let mut broker_size = base_broker();
    broker_size
        .set_capability_advanced_policy(
            &operator(),
            "openai/transcription",
            CapabilityAdvancedPolicy {
                rate_limit_per_minute: None,
                max_request_body_bytes: Some(4),
                max_response_body_bytes: None,
                response_body_blocklist: Vec::new(),
            },
        )
        .unwrap();
    let token = mint_token(
        &mut broker_size,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let err = broker_size
        .execute_envelope(
            &RequestAuth::Proxy(token.token),
            ProxyEnvelope {
                capability: "openai/transcription".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "POST".to_string(),
                    path: "/v1/audio/transcriptions".to_string(),
                    headers: Vec::new(),
                    body: Some("12345".to_string()),
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            loopback_ip(),
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
    assert!(err
        .message
        .contains("request body exceeds capability size limit"));
}

#[test]
fn story_adv_response_body_filtering() {
    let mut broker = base_broker();
    broker
        .set_capability_advanced_policy(
            &operator(),
            "openai/transcription",
            CapabilityAdvancedPolicy {
                rate_limit_per_minute: None,
                max_request_body_bytes: None,
                max_response_body_bytes: Some(64),
                response_body_blocklist: vec!["secret-token".to_string()],
            },
        )
        .unwrap();

    let forwarded = broker
        .forward_response_for_capability(
            "openai/transcription",
            UpstreamResponse {
                status: 200,
                headers: vec![
                    Header {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    },
                    Header {
                        name: "connection".to_string(),
                        value: "keep-alive".to_string(),
                    },
                ],
                body_chunks: vec![br#"{"token":"secret-token","ok":true}"#.to_vec()],
            },
        )
        .unwrap();
    assert_eq!(forwarded.headers.len(), 1);
    let filtered_body = String::from_utf8(forwarded.body_chunks.concat()).unwrap();
    assert!(filtered_body.contains("[REDACTED]"));
    assert!(!filtered_body.contains("secret-token"));

    let err = broker
        .forward_response_for_capability(
            "openai/transcription",
            UpstreamResponse {
                status: 200,
                headers: vec![],
                body_chunks: vec![vec![b'x'; 65]],
            },
        )
        .unwrap_err();
    assert_eq!(err.error, ErrorCode::PolicyViolation);
    assert!(err
        .message
        .contains("response body exceeds capability size limit"));
}

#[test]
fn story_conf_core_level_minimum() {
    let broker = base_broker();
    let levels = broker.conformance_levels();
    assert_eq!(levels.get("Core"), Some(&true));
}

#[test]
fn story_conf_registry_level_optional() {
    let broker = base_broker();
    let levels = broker.conformance_levels();
    assert_eq!(levels.get("Registry"), Some(&true));
}

#[test]
fn story_conf_oauth2_level() {
    let broker = base_broker();
    let levels = broker.conformance_levels();
    assert_eq!(levels.get("OAuth2"), Some(&true));
}

#[test]
fn story_conf_websocket_level() {
    let broker = base_broker();
    let levels = broker.conformance_levels();
    assert_eq!(levels.get("WebSocket"), Some(&true));
}

#[test]
fn story_conf_signing_level() {
    let broker = base_broker();
    let levels = broker.conformance_levels();
    assert_eq!(levels.get("Signing"), Some(&true));
}

#[test]
fn story_conf_mtls_level() {
    let broker = base_broker();
    let levels = broker.conformance_levels();
    assert_eq!(levels.get("mTLS"), Some(&true));
}

#[test]
fn story_conf_success_criteria_zero_trust_outcomes() {
    let mut broker = base_broker();
    let token = mint_token(
        &mut broker,
        vec!["openai/transcription"],
        Some("openai"),
        60_000,
    );
    let planned = broker
        .execute_passthrough(
            &RequestAuth::Proxy(token.token),
            "POST",
            "/v/openai/v1/audio/transcriptions",
            Vec::new(),
            loopback_ip(),
        )
        .unwrap();
    assert_eq!(planned.planned.host, "api.openai.com");
    assert_eq!(planned.planned.credential, "openai");
}
