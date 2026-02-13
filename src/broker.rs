use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

mod helpers;
mod runtime;
#[cfg(test)]
mod tests;

pub use self::helpers::host_matches;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    PolicyViolation,
    CapabilityNotFound,
    CredentialNotFound,
    CredentialAmbiguous,
    VaultUnavailable,
    AuthFailed,
    OauthRefreshRequired,
    UpstreamUnreachable,
    TokenInvalid,
    InvalidRequest,
    OperatorAuthRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerError {
    pub error: ErrorCode,
    pub message: String,
}

impl BrokerError {
    fn new(error: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.error, self.message)
    }
}

impl std::error::Error for BrokerError {}

pub type BrokerResult<T> = Result<T, BrokerError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthHeaderTemplate {
    pub header_name: String,
    pub value_template: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrategy {
    Header {
        header_name: String,
        value_template: String,
    },
    /// Broker-managed path rewriting with secret injection (e.g. Telegram Bot API token-in-path).
    ///
    /// Callers supply the logical upstream path without the secret-bearing prefix; the broker
    /// prepends a rendered prefix to the outgoing path after policy checks.
    Path {
        /// Template that must include exactly one `{{secret}}` placeholder.
        prefix_template: String,
    },
    Query {
        param_name: String,
    },
    /// Inject multiple headers derived from a multi-field secret payload.
    ///
    /// Templates may reference fields using `{{fieldName}}` placeholders.
    MultiHeader(Vec<AuthHeaderTemplate>),
    Basic,
    OAuth2 {
        grant_type: String,
        token_endpoint: String,
        #[serde(default)]
        scopes: Vec<String>,
    },
    AwsSigV4 {
        service: String,
        region: String,
    },
    Hmac {
        algorithm: String,
        header_name: String,
        value_template: String,
    },
    Mtls,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretMaterial {
    String(String),
    Fields(HashMap<String, String>),
    Basic {
        username: String,
        password: String,
    },
    OAuth2 {
        client_id: String,
        client_secret: String,
        refresh_token: String,
        access_token: Option<String>,
        access_token_expires_at_ms: Option<i64>,
    },
    Aws {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    Hmac {
        secret: String,
    },
    Mtls {
        cert_pem: String,
        key_pem: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInput {
    pub id: String,
    pub provider: String,
    #[serde(default)]
    pub auth: Option<AuthStrategy>,
    #[serde(default)]
    pub hosts: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub id: String,
    pub provider: String,
    pub auth: AuthStrategy,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowPolicy {
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub path_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAdvancedPolicy {
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
    #[serde(default)]
    pub max_request_body_bytes: Option<usize>,
    #[serde(default)]
    pub max_response_body_bytes: Option<usize>,
    #[serde(default)]
    pub response_body_blocklist: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    pub provider: String,
    pub allow: AllowPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderTemplate {
    pub provider: String,
    pub auth: AuthStrategy,
    pub hosts: Vec<String>,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Default)]
pub struct Registry {
    providers: HashMap<String, ProviderTemplate>,
}

impl Registry {
    pub fn from_templates(templates: Vec<ProviderTemplate>) -> BrokerResult<Self> {
        let mut providers = HashMap::new();
        for template in templates {
            if providers
                .insert(template.provider.clone(), template)
                .is_some()
            {
                return Err(BrokerError::new(
                    ErrorCode::InvalidRequest,
                    "duplicate provider in registry",
                ));
            }
        }
        Ok(Self { providers })
    }

    pub fn provider(&self, provider: &str) -> Option<&ProviderTemplate> {
        self.providers.get(provider)
    }

    pub fn providers(&self) -> Vec<ProviderTemplate> {
        self.providers.values().cloned().collect()
    }

    /// Lookup a capability by id across all registry providers.
    ///
    /// This is used to canonicalize policy derived from compiled-in registry templates when
    /// loading potentially untrusted persisted config.
    pub fn capability(&self, capability_id: &str) -> Option<Capability> {
        let capability_id = capability_id.trim();
        if capability_id.is_empty() {
            return None;
        }
        for template in self.providers.values() {
            if let Some(cap) = template.capabilities.iter().find(|c| c.id == capability_id) {
                return Some(cap.clone());
            }
        }
        None
    }

    pub fn from_json_str(raw: &str) -> BrokerResult<Self> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RegistryJson {
            Wrapped { providers: Vec<ProviderTemplate> },
            Flat(Vec<ProviderTemplate>),
        }

        let parsed = serde_json::from_str::<RegistryJson>(raw).map_err(|err| {
            BrokerError::new(
                ErrorCode::InvalidRequest,
                format!("invalid registry JSON: {}", err),
            )
        })?;

        let templates = match parsed {
            RegistryJson::Wrapped { providers } => providers,
            RegistryJson::Flat(providers) => providers,
        };
        Self::from_templates(templates)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestAuth {
    Operator(String),
    Proxy(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyToken {
    pub token: String,
    pub capabilities: Vec<String>,
    pub credential: Option<String>,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTokenMintRequest {
    pub capabilities: Vec<String>,
    pub credential: Option<String>,
    pub ttl_ms: i64,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerConfig {
    pub core_exact_hosts_only: bool,
    pub allow_remote_clients: bool,
    pub allow_http_local_extension: bool,
    pub allow_non_default_ports_extension: bool,
    pub redirect_mode: RedirectMode,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            core_exact_hosts_only: true,
            allow_remote_clients: false,
            allow_http_local_extension: false,
            allow_non_default_ports_extension: false,
            redirect_mode: RedirectMode::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectMode {
    Block,
    Revalidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSecret {
    pub id: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub ts_ms: i64,
    pub capability: String,
    pub credential: String,
    pub host: String,
    #[serde(default)]
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBodyMode {
    Empty,
    Text(String),
    Multipart {
        fields: HashMap<String, String>,
        files: Vec<MultipartFile>,
    },
    BodyFilePath(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartFile {
    pub field: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRequest {
    pub capability: String,
    pub credential: String,
    pub host: String,
    pub scheme: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<Header>,
    pub query: Vec<(String, String)>,
    pub body_mode: RequestBodyMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPassthrough {
    pub planned: PlannedRequest,
    pub matched_capabilities: Vec<String>,
    pub audit_capability: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body_chunks: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body_chunks: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProxyEnvelope {
    pub capability: String,
    #[serde(default)]
    pub credential: Option<String>,
    pub request: ProxyEnvelopeRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProxyEnvelopeRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub multipart: Option<HashMap<String, String>>,
    #[serde(default)]
    pub multipart_files: Vec<MultipartFileSerde>,
    #[serde(default)]
    pub body_file_path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MultipartFileSerde {
    pub field: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WsConnectFrame {
    pub capability: String,
    pub path: String,
    #[serde(default)]
    pub target_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerEnv {
    pub aivault_base_url: String,
    pub aivault_token: String,
}

#[derive(Debug, Default)]
pub struct Broker {
    cfg: BrokerConfig,
    registry: Option<Registry>,
    credentials: HashMap<String, Credential>,
    secrets: HashMap<String, SecretMaterial>,
    capabilities: HashMap<String, Capability>,
    proxy_tokens: HashMap<String, ProxyToken>,
    operator_secrets: HashMap<String, OperatorSecret>,
    advanced_policies: HashMap<String, CapabilityAdvancedPolicy>,
    rate_windows: HashMap<String, (i64, u32)>,
    audit: Vec<AuditRecord>,
}
