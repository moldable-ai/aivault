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

#[test]
fn builtin_notion_registry_keeps_rest_auth_and_scopes_oauth_to_mcp() {
    let registry = builtin_registry().expect("registry should load");
    let notion = registry.provider("notion").expect("notion provider");

    assert_eq!(
        notion.vault_secrets.get("NOTION_TOKEN"),
        Some(&"secret".to_string())
    );
    assert_eq!(
        notion.auth,
        AuthStrategy::Header {
            header_name: "authorization".to_string(),
            value_template: "Bearer {{secret}}".to_string(),
        }
    );
    assert_eq!(notion.hosts, ["api.notion.com"]);

    let oauth = notion
        .credential_alternatives
        .iter()
        .find(|alternative| alternative.id == "mcp-oauth")
        .expect("Notion hosted MCP OAuth credential alternative");
    assert_eq!(
        oauth.vault_secrets.get("NOTION_OAUTH_JSON"),
        Some(&"secret".to_string())
    );
    assert_eq!(
        oauth.auth,
        AuthStrategy::OAuth2 {
            grant_type: "refresh_token".to_string(),
            token_endpoint: "https://mcp.notion.com/token".to_string(),
            scopes: vec!["default".to_string()],
        }
    );
    assert_eq!(oauth.hosts, ["mcp.notion.com"]);
    assert_eq!(oauth.capabilities, ["notion/mcp"]);
    assert_eq!(oauth.priority, 100);

    let mcp = registry
        .capability("notion/mcp")
        .expect("Notion MCP capability");
    assert_eq!(mcp.allow.hosts, ["mcp.notion.com"]);
    assert_eq!(mcp.allow.methods, ["DELETE", "POST"]);
    assert_eq!(mcp.allow.path_prefixes, ["/mcp"]);
}
