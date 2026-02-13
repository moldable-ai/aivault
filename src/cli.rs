use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
pub enum ProviderKind {
    MacosKeychain,
    Env,
    File,
    Passphrase,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ScopeKind {
    Global,
    Workspace,
    Team,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum AuthKind {
    Header,
    Query,
    Basic,
    OAuth2,
    AwsSigv4,
    Hmac,
    Mtls,
}

#[derive(Debug, Parser)]
#[command(name = "aivault")]
#[command(about = "Standalone local vault runtime and CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Status,
    Init {
        #[arg(long, value_enum, default_value_t = ProviderKind::MacosKeychain)]
        provider: ProviderKind,
        #[arg(long)]
        env_var: Option<String>,
        #[arg(long)]
        file_path: Option<String>,
        #[arg(long)]
        keychain_service: Option<String>,
        #[arg(long)]
        keychain_account: Option<String>,
        #[arg(long)]
        passphrase: Option<String>,
    },
    Unlock {
        #[arg(long)]
        passphrase: String,
    },
    Lock,
    RotateMaster {
        #[arg(long)]
        new_key: Option<String>,
        #[arg(long)]
        new_passphrase: Option<String>,
    },
    Audit {
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        before_ts_ms: Option<i64>,
    },
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },
    Capabilities {
        #[command(subcommand)]
        command: CapabilitiesCommand,
    },
    Oauth {
        #[command(subcommand)]
        command: OauthCommand,
    },
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    Capability {
        #[command(subcommand)]
        command: CapabilityCommand,
    },
    Invoke {
        #[command(flatten)]
        args: InvokeArgs,
    },
    Resolve {
        #[arg(long)]
        secret_ref: String,
        #[arg(long)]
        raw: bool,
    },
    ResolveTeam {
        #[arg(long)]
        secret_ref: String,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        team: String,
        #[arg(long)]
        raw: bool,
    },
}

#[derive(Debug, Clone, Args)]
pub struct InvokeArgs {
    #[arg()]
    pub id: String,
    #[arg(long)]
    pub request: Option<String>,
    #[arg(long)]
    pub request_file: Option<String>,
    #[arg(long)]
    pub method: Option<String>,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub header: Vec<String>,
    #[arg(long)]
    pub body: Option<String>,
    #[arg(long)]
    pub body_file_path: Option<String>,
    #[arg(long)]
    pub multipart_field: Vec<String>,
    #[arg(long)]
    pub multipart_file: Vec<String>,
    #[arg(long)]
    pub credential: Option<String>,
    #[arg(long, default_value = "127.0.0.1")]
    pub client_ip: String,
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    List {
        #[arg(long, value_enum)]
        scope: Option<ScopeKind>,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        team: Option<String>,
    },
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        value: String,
        #[arg(long, value_enum, default_value_t = ScopeKind::Global)]
        scope: ScopeKind,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        alias: Vec<String>,
    },
    Update {
        #[arg(long)]
        id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        alias: Vec<String>,
        #[arg(long)]
        clear_aliases: bool,
    },
    Rotate {
        #[arg(long)]
        id: String,
        #[arg(long)]
        value: String,
    },
    Delete {
        #[arg(long)]
        id: String,
    },
    AttachTeam {
        #[arg(long)]
        id: String,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        team: String,
    },
    DetachTeam {
        #[arg(long)]
        id: String,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        team: String,
    },
    Import {
        #[arg(long)]
        entry: Vec<String>,
        #[arg(long, value_enum, default_value_t = ScopeKind::Global)]
        scope: ScopeKind,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        team: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CapabilitiesCommand {
    List {
        #[arg(long)]
        capability: Option<String>,
        #[arg(long, value_enum)]
        scope: Option<ScopeKind>,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        consumer: Option<String>,
    },
    Bind {
        #[arg(long)]
        capability: String,
        #[arg(long)]
        secret_ref: String,
        #[arg(long, value_enum, default_value_t = ScopeKind::Global)]
        scope: ScopeKind,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        consumer: Option<String>,
    },
    Unbind {
        #[arg(long)]
        capability: String,
        #[arg(long, value_enum, default_value_t = ScopeKind::Global)]
        scope: ScopeKind,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        consumer: Option<String>,
    },
    Resolve {
        #[arg(long)]
        capability: String,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        team: Option<String>,
        #[arg(long)]
        consumer: Option<String>,
        #[arg(long)]
        raw: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum OauthCommand {
    Setup {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        auth_url: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        redirect_uri: String,
        #[arg(long)]
        scope: Vec<String>,
        #[arg(long)]
        state: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum CredentialCommand {
    Create {
        #[arg()]
        id: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        secret_ref: String,
        #[arg(long, value_enum)]
        auth: Option<AuthKind>,
        #[arg(long)]
        host: Vec<String>,
        #[arg(long)]
        header_name: Option<String>,
        #[arg(long)]
        value_template: Option<String>,
        #[arg(long)]
        query_param: Option<String>,
        #[arg(long)]
        grant_type: Option<String>,
        #[arg(long)]
        token_endpoint: Option<String>,
        #[arg(long)]
        scope: Vec<String>,
        #[arg(long)]
        aws_service: Option<String>,
        #[arg(long)]
        aws_region: Option<String>,
        #[arg(long)]
        hmac_algorithm: Option<String>,
    },
    List,
    Delete {
        #[arg()]
        id: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum CapabilityCommand {
    Create {
        #[arg()]
        id: String,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        credential: Option<String>,
        #[arg(long)]
        method: Vec<String>,
        #[arg(long)]
        path: Vec<String>,
        #[arg(long)]
        host: Vec<String>,
    },
    List,
    Delete {
        #[arg()]
        id: String,
    },
    Policy {
        #[command(subcommand)]
        command: CapabilityPolicyCommand,
    },
    #[command(alias = "args", alias = "shape", alias = "inspect")]
    Describe {
        #[arg()]
        id: String,
    },
    #[command(alias = "call")]
    Invoke {
        #[command(flatten)]
        args: InvokeArgs,
    },
}

#[derive(Debug, Subcommand)]
pub enum CapabilityPolicyCommand {
    Set {
        #[arg(long)]
        capability: String,
        #[arg(long)]
        rate_limit_per_minute: Option<u32>,
        #[arg(long)]
        max_request_body_bytes: Option<usize>,
        #[arg(long)]
        max_response_body_bytes: Option<usize>,
        #[arg(long)]
        response_block: Vec<String>,
    },
}
