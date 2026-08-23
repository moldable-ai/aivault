use super::builtin_registry;
use crate::broker::AuthStrategy;

#[test]
fn builtin_granola_registry_is_oauth_and_mcp_scoped() {
    let registry = builtin_registry().expect("registry should load");
    let granola = registry.provider("granola").expect("granola provider");

    assert_eq!(
        granola.vault_secrets.get("GRANOLA_OAUTH_JSON"),
        Some(&"secret".to_string())
    );
    assert_eq!(
        granola.auth,
        AuthStrategy::OAuth2 {
            grant_type: "refresh_token".to_string(),
            token_endpoint: "https://mcp-auth.granola.ai/oauth2/token".to_string(),
            scopes: ["mcp", "offline_access", "openid", "profile", "email"]
                .map(str::to_string)
                .to_vec(),
        }
    );
    assert_eq!(granola.hosts, ["mcp-auth.granola.ai", "mcp.granola.ai"]);

    let mcp = registry
        .capability("granola/mcp")
        .expect("granola MCP capability");
    assert_eq!(mcp.allow.hosts, ["mcp.granola.ai"]);
    assert_eq!(mcp.allow.methods, ["POST"]);
    assert_eq!(mcp.allow.path_prefixes, ["/mcp"]);
}
