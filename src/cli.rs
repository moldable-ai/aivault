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
    /// Show vault status and paths
    Status {
        /// Show full JSON detail
        #[arg(long, short)]
        verbose: bool,
    },
    /// Initialize the vault with a key provider
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
    /// Unlock a passphrase-protected vault
    Unlock {
        #[arg(long)]
        passphrase: String,
    },
    /// Lock a passphrase-protected vault
    Lock,
    /// Rotate the vault master encryption key
    RotateMaster {
        #[arg(long)]
        new_key: Option<String>,
        #[arg(long)]
        new_passphrase: Option<String>,
    },
    /// View audit log events
    Audit {
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        before_ts_ms: Option<i64>,
    },
    /// Manage encrypted secrets
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },
    /// OAuth2 setup helpers
    Oauth {
        #[command(subcommand)]
        command: OauthCommand,
    },
    /// Manage provider credentials
    Credential {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    /// Manage capability definitions (list, describe, invoke)
    Capability {
        #[command(subcommand)]
        command: CapabilityCommand,
    },
    /// Invoke a capability and print the raw upstream response
    Invoke {
        #[command(flatten)]
        args: InvokeArgs,
    },
    /// Invoke a capability and print the response as JSON
    Json {
        #[command(flatten)]
        args: InvokeArgs,
    },
    /// Invoke a capability and print the response as markdown
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
    /// System setup helpers (cross-user agent access, service installation)
    Setup {
        #[command(subcommand)]
        command: SetupCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum SetupCommand {
    /// Configure OS group membership and shared socket directory for cross-user invocation
    AgentAccess {
        /// The OS user your untrusted agent runs as
        #[arg(long)]
        agent_user: String,
        /// The OS user that will run aivaultd (defaults to $SUDO_USER)
        #[arg(long)]
        daemon_user: Option<String>,
        /// Print what would change without applying it
        #[arg(long)]
        dry_run: bool,
    },
    /// Install/enable a launchd LaunchAgent to run `aivaultd --shared` (macOS)
    Launchd {
        /// Print what would change without applying it
        #[arg(long)]
        dry_run: bool,
    },
    /// Install/enable a systemd service to run `aivaultd --shared` (Linux)
    Systemd {
        /// The OS user that will run aivaultd (commonly: aivault)
        #[arg(long)]
        daemon_user: String,
        /// Print what would change without applying it
        #[arg(long)]
        dry_run: bool,
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
    /// List secrets (metadata only, no values)
    List {
        #[arg(long, value_enum)]
        scope: Option<ScopeKind>,
        #[arg(long)]
        workspace_id: Option<String>,
        #[arg(long)]
        group_id: Option<String>,
        /// Show full JSON detail
        #[arg(long, short)]
        verbose: bool,
    },
    /// Create a new encrypted secret
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
    /// Update secret name or aliases
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
    /// Rotate a secret's encrypted value
    Rotate {
        #[arg(long)]
        id: String,
        #[arg(long)]
        value: String,
    },
    /// Revoke and delete a secret
    Delete {
        #[arg(long)]
        id: String,
    },
    /// Attach a secret to a workspace group
    AttachGroup {
        #[arg(long)]
        id: String,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        group_id: String,
    },
    /// Detach a secret from a workspace group
    DetachGroup {
        #[arg(long)]
        id: String,
        #[arg(long)]
        workspace_id: String,
        #[arg(long)]
        group_id: String,
    },
    /// Bulk import secrets from KEY=VALUE pairs
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
    /// Create a credential binding a provider to a secret
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
    /// List configured credentials
    List {
        /// Show full JSON detail
        #[arg(long, short)]
        verbose: bool,
    },
    /// Delete a credential
    Delete {
        #[arg()]
        id: String,
    },
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum CapabilityCommand {
    /// Create a custom capability definition
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
    /// List all available capabilities (registered + registry)
    List {
        /// Show full JSON detail for each capability
        #[arg(long, short)]
        verbose: bool,
    },
    /// Delete a capability definition
    Delete {
        #[arg()]
        id: String,
    },
    /// Set advanced policy (rate limits, size limits, response filtering)
    Policy {
        #[command(subcommand)]
        command: CapabilityPolicyCommand,
    },
    /// Show how to invoke a capability (allowed methods, paths, examples)
    #[command(alias = "args", alias = "shape", alias = "inspect")]
    Describe {
        #[arg()]
        id: String,
    },
    /// Invoke a capability and print the raw upstream response
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
    /// Bind a capability to a vault secret reference
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
    /// Remove a capability-to-secret binding
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
    /// List capability-to-secret bindings
    Bindings {
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
        /// Show full JSON detail
        #[arg(long, short)]
        verbose: bool,
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
