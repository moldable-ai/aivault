use std::collections::{BTreeMap, BTreeSet};

use colored::Colorize;

use crate::broker::{AuthStrategy, Capability, ProviderTemplate};
use crate::broker_store::StoredCredential;
use crate::capabilities::{CapabilityBinding, CapabilityScope};
use crate::vault::{SecretMeta, SecretScope, VaultProviderType, VaultStatus};

// ── Palette ──────────────────────────────────────────────────────────────────
// Consistent color vocabulary used across every command.
//
//   heading   – bold cyan   (section titles)
//   label     – bold        (field names / keys)
//   value     – normal      (field values)
//   id        – bright cyan (identifiers the user can copy/paste)
//   dim       – dimmed      (secondary info, hints)
//   ok        – green       (healthy / success)
//   warn      – yellow      (needs attention)

/// Print a section heading.
pub fn heading(text: &str) {
    println!("{}", text.bold().cyan());
}

/// Print a blank separator line.
pub fn separator() {
    println!();
}

/// Format a label: value line (indented).
pub fn kv(label: &str, value: &str) {
    println!("  {} {}", format!("{}:", label).bold(), value);
}

/// Format a label: value line where the value is dimmed.
pub fn kv_dim(label: &str, value: &str) {
    println!("  {} {}", format!("{}:", label).bold(), value.dimmed());
}

/// Print a hint/footer line.
pub fn hint(text: &str) {
    println!("{}", text.dimmed());
}

/// Print a count summary line.
pub fn summary(count: usize, noun: &str) {
    let plural = if count == 1 { "" } else { "s" };
    println!("{}", format!("{} {}{}", count, noun, plural).dimmed());
}

// ── Status ───────────────────────────────────────────────────────────────────

pub fn print_status(status: &VaultStatus, root_dir: &str) {
    heading("Vault");

    let state = if !status.enabled {
        "not initialized".yellow().to_string()
    } else if status.locked {
        "locked".yellow().to_string()
    } else {
        "unlocked".green().to_string()
    };
    kv("Status", &state);

    if let Some(ref provider) = status.provider_type {
        kv("Provider", &format_provider_type(provider));
    }
    if let Some(ref kek_id) = status.kek_id {
        // This is a fingerprint/identifier, not the KEK bytes.
        kv_dim("KEK identifier", kek_id);
    }

    separator();
    heading("Paths");
    kv_dim("Root", root_dir);
}

fn format_provider_type(p: &VaultProviderType) -> String {
    match p {
        VaultProviderType::MacosKeychain => "macOS Keychain".to_string(),
        VaultProviderType::Passphrase => "Passphrase".to_string(),
        VaultProviderType::Env => "Environment variable".to_string(),
        VaultProviderType::File => "Key file".to_string(),
    }
}

// ── Secrets ──────────────────────────────────────────────────────────────────

pub fn print_secrets_list(secrets: &[SecretMeta]) {
    if secrets.is_empty() {
        println!("{}", "No secrets found.".dimmed());
        return;
    }

    heading("Secrets");
    for (i, meta) in secrets.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("  {}", meta.name.bright_cyan());
        kv_dim("    ID", &meta.secret_id);
        kv("    Scope", &format_secret_scope(&meta.scope));
        if !meta.aliases.is_empty() {
            kv_dim("    Aliases", &meta.aliases.join(", "));
        }
        if meta.revoked_at_ms.is_some() {
            println!("    {}", "REVOKED".red().bold());
        }
    }
    separator();
    summary(secrets.len(), "secret");
    hint("Use --verbose for full JSON detail.");
}

fn format_secret_scope(scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => "global".to_string(),
        SecretScope::Workspace { workspace_id } => format!("workspace:{}", workspace_id),
        SecretScope::Group {
            workspace_id,
            group_id,
        } => format!("group:{}:{}", workspace_id, group_id),
    }
}

// ── Credentials ──────────────────────────────────────────────────────────────

pub fn print_credentials_list(credentials: &[StoredCredential]) {
    if credentials.is_empty() {
        println!("{}", "No credentials found.".dimmed());
        return;
    }

    heading("Credentials");
    for (i, cred) in credentials.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("  {}", cred.id.bright_cyan());
        kv("    Provider", &cred.provider);
        kv("    Auth", &format_auth_strategy(&cred.auth));
        kv_dim("    Hosts", &cred.hosts.join(", "));
        if let Some(ref ws) = cred.workspace_id {
            if let Some(ref g) = cred.group_id {
                kv_dim("    Scope", &format!("group:{}:{}", ws, g));
            } else {
                kv_dim("    Scope", &format!("workspace:{}", ws));
            }
        }
    }
    separator();
    summary(credentials.len(), "credential");
    hint("Use --verbose for full JSON detail.");
}

fn format_auth_strategy(auth: &AuthStrategy) -> String {
    match auth {
        AuthStrategy::Header { .. } => "header".to_string(),
        AuthStrategy::Path { .. } => "path".to_string(),
        AuthStrategy::Query { .. } => "query".to_string(),
        AuthStrategy::MultiHeader(_) => "multi-header".to_string(),
        AuthStrategy::MultiQuery(_) => "multi-query".to_string(),
        AuthStrategy::Basic => "basic".to_string(),
        AuthStrategy::OAuth2 { .. } => "oauth2".to_string(),
        AuthStrategy::AwsSigV4 { .. } => "aws-sigv4".to_string(),
        AuthStrategy::Hmac { .. } => "hmac".to_string(),
        AuthStrategy::Mtls => "mtls".to_string(),
    }
}

// ── Capability bindings ──────────────────────────────────────────────────────

pub fn print_bindings_list(bindings: &[CapabilityBinding]) {
    if bindings.is_empty() {
        println!("{}", "No capability bindings found.".dimmed());
        return;
    }

    heading("Capability bindings");
    for (i, b) in bindings.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!(
            "  {} {} {}",
            b.capability.bright_cyan(),
            "->".dimmed(),
            b.secret_ref.dimmed()
        );
        kv("    Scope", &format_capability_scope(&b.scope));
        if let Some(ref consumer) = b.consumer {
            kv_dim("    Consumer", consumer);
        }
    }
    separator();
    summary(bindings.len(), "binding");
    hint("Use --verbose for full JSON detail.");
}

fn format_capability_scope(scope: &CapabilityScope) -> String {
    match scope {
        CapabilityScope::Global => "global".to_string(),
        CapabilityScope::Workspace { workspace_id } => format!("workspace:{}", workspace_id),
        CapabilityScope::Group {
            workspace_id,
            group_id,
        } => format!("group:{}:{}", workspace_id, group_id),
    }
}

// ── Capability definitions ───────────────────────────────────────────────────

pub fn print_capabilities_list(
    local: &[Capability],
    registry: &[Capability],
    registry_providers: &[ProviderTemplate],
) {
    if local.is_empty() && registry.is_empty() {
        println!("{}", "No capabilities found.".dimmed());
        return;
    }

    if !registry.is_empty() {
        heading("Available (needs credential)");

        // Group registry capabilities by provider and show required vault secret names.
        let provider_map: BTreeMap<&str, &ProviderTemplate> = registry_providers
            .iter()
            .map(|p| (p.provider.as_str(), p))
            .collect();
        let mut by_provider: BTreeMap<&str, Vec<&Capability>> = BTreeMap::new();
        for cap in registry {
            by_provider
                .entry(cap.provider.as_str())
                .or_default()
                .push(cap);
        }

        for (provider, caps) in &by_provider {
            println!("  {}", provider.bold());
            for cap in caps {
                println!("    {}", cap.id.as_str().dimmed());
            }
            if let Some(template) = provider_map.get(provider) {
                if !template.vault_secrets.is_empty() {
                    let names: BTreeSet<&str> =
                        template.vault_secrets.keys().map(|s| s.as_str()).collect();
                    let setup_cmds: Vec<String> = names
                        .iter()
                        .map(|name| {
                            format!(
                                "aivault secrets create --name {} --value \"...\" --scope global",
                                name
                            )
                        })
                        .collect();
                    println!(
                        "    {} {}",
                        "Setup:".bold(),
                        setup_cmds.join(" && ").dimmed()
                    );
                }
            }
        }
    }
    if !local.is_empty() {
        if !registry.is_empty() {
            separator();
        }
        heading("Ready (credential configured)");
        let mut sorted: Vec<&Capability> = local.iter().collect();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        for cap in sorted {
            println!("  {}", cap.id.bright_cyan());
        }
    }
    separator();
    let total = local.len() + registry.len();
    summary(total, "capability");
    hint("Use --verbose for full JSON, or `aivault capability describe <id>` to inspect one.");
}
