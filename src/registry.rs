use include_dir::{include_dir, Dir};

use crate::broker::{BrokerResult, ErrorCode, ProviderTemplate, Registry};

static REGISTRY_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/registry");

fn parse_provider_template(raw: &str, source: &str) -> BrokerResult<ProviderTemplate> {
    serde_json::from_str(raw).map_err(|err| crate::broker::BrokerError {
        error: ErrorCode::InvalidRequest,
        message: format!("invalid built-in registry provider '{}': {}", source, err),
    })
}

pub fn builtin_registry() -> BrokerResult<Registry> {
    let mut json_files: Vec<_> = REGISTRY_DIR
        .files()
        .filter(|file| file.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .filter(|file| !file.path().starts_with("schemas"))
        .collect();
    json_files.sort_by(|a, b| a.path().cmp(b.path()));

    let mut templates = Vec::new();
    for file in json_files {
        let source = file.path().to_string_lossy().to_string();
        let raw = file
            .contents_utf8()
            .ok_or_else(|| crate::broker::BrokerError {
                error: ErrorCode::InvalidRequest,
                message: format!("invalid utf-8 in built-in registry provider '{}'", source),
            })?;
        templates.push(parse_provider_template(raw, &source)?);
    }
    Registry::from_templates(templates)
}

#[cfg(test)]
mod managed_mcp_tests;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::broker::{
        AuthStrategy, Broker, BrokerConfig, CredentialInput, ErrorCode, ProxyEnvelope,
        ProxyEnvelopeRequest, ProxyTokenMintRequest, RequestAuth, SecretMaterial,
    };

    const TELEGRAM_OPERATIONS: [(&str, &str); 6] = [
        ("telegram/get-me", "/getMe"),
        ("telegram/get-updates", "/getUpdates"),
        ("telegram/send-message", "/sendMessage"),
        ("telegram/edit-message-text", "/editMessageText"),
        ("telegram/delete-message", "/deleteMessage"),
        ("telegram/send-chat-action", "/sendChatAction"),
    ];

    #[test]
    fn builtin_registry_contains_initial_transcription_providers() {
        let registry = builtin_registry().expect("registry should load");

        let openai = registry.provider("openai").expect("openai provider");
        assert!(openai
            .capabilities
            .iter()
            .any(|cap| cap.id == "openai/transcription"));

        let remove_bg = registry.provider("remove-bg").expect("remove-bg provider");
        assert!(remove_bg
            .capabilities
            .iter()
            .any(|cap| cap.id == "remove-bg/background-removal"));

        let deepgram = registry.provider("deepgram").expect("deepgram provider");
        assert!(deepgram
            .capabilities
            .iter()
            .any(|cap| cap.id == "deepgram/transcription"));

        let elevenlabs = registry
            .provider("elevenlabs")
            .expect("elevenlabs provider");
        assert!(elevenlabs
            .capabilities
            .iter()
            .any(|cap| cap.id == "elevenlabs/transcription"));

        let gmail = registry
            .provider("google-gmail")
            .expect("google-gmail provider");
        assert!(gmail
            .capabilities
            .iter()
            .any(|cap| cap.id == "google-gmail/messages-read"));
        assert!(gmail
            .capabilities
            .iter()
            .any(|cap| cap.id == "google-gmail/send"));
        assert!(gmail
            .capabilities
            .iter()
            .any(|cap| cap.id == "google-gmail/contacts-read"));
        let send_as = gmail
            .capabilities
            .iter()
            .find(|cap| cap.id == "google-gmail/send-as-read")
            .expect("google-gmail send-as capability");
        assert_eq!(send_as.allow.methods, ["GET"].map(str::to_string));
        assert_eq!(
            send_as.allow.path_prefixes,
            ["/gmail/v1/users/me/settings/sendAs".to_string()]
        );
        let drafts = gmail
            .capabilities
            .iter()
            .find(|cap| cap.id == "google-gmail/drafts")
            .expect("google-gmail drafts capability");
        assert_eq!(
            drafts.allow.methods,
            ["DELETE", "GET", "POST", "PUT"].map(str::to_string)
        );
        assert_eq!(
            drafts.allow.path_prefixes,
            ["/gmail/v1/users/me/drafts".to_string()]
        );

        let calendar = registry
            .provider("google-calendar")
            .expect("google-calendar provider");
        assert!(calendar
            .capabilities
            .iter()
            .any(|cap| cap.id == "google-calendar/events"));
    }

    #[test]
    fn builtin_openai_registry_scopes_codex_usage_to_read_only_oauth() {
        let registry = builtin_registry().expect("registry should load");
        let openai = registry.provider("openai").expect("openai provider");
        let usage = openai
            .capabilities
            .iter()
            .find(|cap| cap.id == "openai/codex-usage")
            .expect("codex usage capability");

        assert_eq!(usage.allow.hosts, ["chatgpt.com"]);
        assert_eq!(usage.allow.methods, ["GET"]);
        assert_eq!(usage.allow.path_prefixes, ["/wham/usage"]);

        let credential = openai
            .credential_alternatives
            .iter()
            .find(|alternative| alternative.id == "codex-oauth-usage")
            .expect("codex usage credential");
        assert_eq!(credential.capabilities, ["openai/codex-usage"]);
        assert_eq!(
            credential.upstream_path_prefix.as_deref(),
            Some("/backend-api")
        );
        assert_eq!(
            credential.vault_secrets.get("CODEX_OAUTH_JSON"),
            Some(&"oauth".to_string())
        );
    }

    #[test]
    fn builtin_openai_registry_scopes_codex_realtime_to_call_creation() {
        let registry = builtin_registry().expect("registry should load");
        let openai = registry.provider("openai").expect("openai provider");
        let realtime = openai
            .capabilities
            .iter()
            .find(|cap| cap.id == "openai/codex-realtime")
            .expect("codex realtime capability");

        assert_eq!(realtime.allow.hosts, ["chatgpt.com"]);
        assert_eq!(realtime.allow.methods, ["POST"]);
        assert_eq!(realtime.allow.path_prefixes, ["/realtime/calls"]);

        let credential = openai
            .credential_alternatives
            .iter()
            .find(|alternative| alternative.id == "codex-oauth")
            .expect("codex oauth credential");
        assert!(credential
            .capabilities
            .iter()
            .any(|capability| capability == "openai/codex-realtime"));
        assert_eq!(
            credential.upstream_path_prefix.as_deref(),
            Some("/backend-api/codex")
        );
    }

    #[test]
    fn builtin_registry_contains_firecrawl_provider() {
        let registry = builtin_registry().expect("registry should load");

        let firecrawl = registry.provider("firecrawl").expect("firecrawl provider");
        assert_eq!(
            firecrawl.vault_secrets.get("FIRECRAWL_API_KEY"),
            Some(&"secret".to_string())
        );

        for expected in [
            "firecrawl/agent",
            "firecrawl/batch-scrape",
            "firecrawl/browser",
            "firecrawl/crawl",
            "firecrawl/map",
            "firecrawl/parse",
            "firecrawl/scrape",
            "firecrawl/search",
            "firecrawl/support",
        ] {
            assert!(
                firecrawl.capabilities.iter().any(|cap| cap.id == expected),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn builtin_agentmail_registry_is_oauth_and_mcp_scoped() {
        let registry = builtin_registry().expect("registry should load");
        let agentmail = registry.provider("agentmail").expect("agentmail provider");

        assert_eq!(
            agentmail.vault_secrets.get("AGENTMAIL_OAUTH_JSON"),
            Some(&"secret".to_string())
        );
        assert_eq!(
            agentmail.auth,
            AuthStrategy::OAuth2 {
                grant_type: "refresh_token".to_string(),
                token_endpoint: "https://clerk.console.agentmail.to/oauth/token".to_string(),
                scopes: ["openid", "profile", "email", "offline_access"]
                    .map(str::to_string)
                    .to_vec(),
            }
        );
        assert_eq!(
            agentmail.hosts,
            ["clerk.console.agentmail.to", "mcp.agentmail.to"]
        );

        let mcp = registry
            .capability("agentmail/mcp")
            .expect("agentmail MCP capability");
        assert_eq!(mcp.allow.hosts, ["mcp.agentmail.to"]);
        assert_eq!(mcp.allow.methods, ["DELETE", "POST"]);
        assert_eq!(mcp.allow.path_prefixes, ["/mcp"]);
    }

    #[test]
    fn builtin_telegram_registry_is_path_authenticated_and_least_privilege() {
        let registry = builtin_registry().expect("registry should load");
        let telegram = registry.provider("telegram").expect("telegram provider");

        assert_eq!(
            telegram.auth,
            AuthStrategy::Path {
                prefix_template: "/bot{{secret}}".to_string(),
            }
        );

        let mut actual = telegram
            .capabilities
            .iter()
            .map(|capability| {
                assert_eq!(capability.provider, "telegram");
                assert_eq!(capability.allow.hosts, ["api.telegram.org"]);
                assert_eq!(capability.allow.methods, ["POST"]);
                assert_eq!(capability.allow.path_prefixes.len(), 1);
                (
                    capability.id.as_str(),
                    capability.allow.path_prefixes[0].as_str(),
                )
            })
            .collect::<Vec<_>>();
        actual.sort_unstable();

        let mut expected = TELEGRAM_OPERATIONS.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected);
        assert!(registry.capability("telegram/bot").is_none());
    }

    #[test]
    fn builtin_telegram_capabilities_inject_path_auth_and_reject_broad_methods() {
        let registry = builtin_registry().expect("registry should load");
        let mut broker = Broker::new(BrokerConfig::default(), Some(registry));
        let operator = RequestAuth::Operator("test".to_string());
        broker
            .create_credential(
                &operator,
                CredentialInput {
                    id: "telegram-test".to_string(),
                    provider: "telegram".to_string(),
                    auth: None,
                    hosts: None,
                },
                SecretMaterial::String("123456789:telegram-test-token".to_string()),
            )
            .expect("registry credential should be created");

        let proxy = broker
            .mint_proxy_token(
                &operator,
                ProxyTokenMintRequest {
                    capabilities: TELEGRAM_OPERATIONS
                        .iter()
                        .map(|(capability, _)| (*capability).to_string())
                        .collect(),
                    credential: Some("telegram-test".to_string()),
                    ttl_ms: 60_000,
                    context: HashMap::new(),
                },
            )
            .expect("proxy token should be minted");
        let auth = RequestAuth::Proxy(proxy.token);

        for (capability, logical_path) in TELEGRAM_OPERATIONS {
            let planned = broker
                .execute_envelope(
                    &auth,
                    ProxyEnvelope {
                        capability: capability.to_string(),
                        credential: Some("telegram-test".to_string()),
                        request: ProxyEnvelopeRequest {
                            method: "POST".to_string(),
                            path: logical_path.to_string(),
                            headers: Vec::new(),
                            body: Some("{}".to_string()),
                            multipart: None,
                            multipart_files: Vec::new(),
                            body_file_path: None,
                            url: None,
                        },
                    },
                    "127.0.0.1".parse().unwrap(),
                )
                .expect("Telegram operation should plan");

            assert_eq!(
                planned.path,
                format!("/bot123456789:telegram-test-token{logical_path}")
            );
            assert_eq!(planned.host, "api.telegram.org");
            assert!(planned.headers.is_empty());
            assert!(planned.query.is_empty());
        }

        let error = broker
            .execute_envelope(
                &auth,
                ProxyEnvelope {
                    capability: "telegram/get-me".to_string(),
                    credential: Some("telegram-test".to_string()),
                    request: ProxyEnvelopeRequest {
                        method: "POST".to_string(),
                        path: "/setWebhook".to_string(),
                        headers: Vec::new(),
                        body: Some("{}".to_string()),
                        multipart: None,
                        multipart_files: Vec::new(),
                        body_file_path: None,
                        url: None,
                    },
                },
                "127.0.0.1".parse().unwrap(),
            )
            .expect_err("unregistered Telegram methods must be rejected");
        assert_eq!(error.error, ErrorCode::PolicyViolation);
    }
}
