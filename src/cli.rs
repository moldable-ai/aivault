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
    Group,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum AuthKind {
    Header,
    Path,
    Query,
    MultiHeader,
    Basic,
    #[value(name = "oauth2", alias = "o-auth2")]
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
    /// Invoke a capability and print the upstream response parsed as JSON.
    Json {
        #[command(flatten)]
        args: InvokeArgs,
    },
    /// Invoke a capability and print the upstream response converted to markdown.
    #[command(alias = "md")]
    Markdown {
        #[command(flatten)]
        args: InvokeArgs,
        /// Namespace to wrap the markdown in (e.g. "data" -> <begin data> ... </end data>)
        #[arg(long)]
        namespace: Option<String>,
        /// Fields to exclude from the markdown output
        #[arg(long)]
        exclude_field: Vec<String>,
        /// Fields to wrap in begin/end tags (for fields containing markdown)
        #[arg(long)]
        wrap_field: Vec<String>,
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
    /// Optional workspace/group execution context for credential resolution and audit context.
    #[arg(long)]
    pub workspace_id: Option<String>,
    #[arg(long)]
    pub group_id: Option<String>,
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
        group_id: Option<String>,
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
        group_id: Option<String>,
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
    AttachGroup {
        #[arg(long)]
        id: String,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        group_id: String,
    },
    DetachGroup {
        #[arg(long)]
        id: String,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        group_id: String,
    },
    Import {
        #[arg(long)]
        entry: Vec<String>,
        #[arg(long, value_enum, default_value_t = ScopeKind::Global)]
        scope: ScopeKind,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        group_id: Option<String>,
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
        group_id: Option<String>,
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
        group_id: Option<String>,
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
        group_id: Option<String>,
        #[arg(long)]
        consumer: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::error::ErrorKind;
    use clap::Parser;

    #[test]
    fn cli_rejects_plaintext_secret_resolution_commands() {
        let err =
            Cli::try_parse_from(["aivault", "resolve", "--secret-ref", "secret:abc"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);

        let err = Cli::try_parse_from([
            "aivault",
            "resolve-group",
            "--secret-ref",
            "secret:abc",
            "--workspace-id",
            "ws",
            "--group-id",
            "group",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);

        let err = Cli::try_parse_from(["aivault", "capabilities", "resolve", "--capability", "x"])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidSubcommand);
    }
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
        /// Optional workspace/group execution context this credential is intended for.
        /// If provided, invoke paths must supply matching `--workspace-id/--group-id`.
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        group_id: Option<String>,
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
        #[arg(long)]
        path_prefix_template: Option<String>,
        /// Repeatable auth header injection templates for multi-header auth.
        /// Format: NAME=TEMPLATE (templates can reference secret fields like {{api_key}}).
        #[arg(long)]
        auth_header: Vec<String>,
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
    /// Invoke a capability and print the upstream response parsed as JSON.
    Json {
        #[command(flatten)]
        args: InvokeArgs,
    },
    /// Invoke a capability and print the upstream response converted to markdown.
    #[command(alias = "md")]
    Markdown {
        #[command(flatten)]
        args: InvokeArgs,
        #[arg(long)]
        namespace: Option<String>,
        #[arg(long)]
        exclude_field: Vec<String>,
        #[arg(long)]
        wrap_field: Vec<String>,
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
