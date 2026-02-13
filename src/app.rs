use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use reqwest::blocking::multipart::Form;
use reqwest::blocking::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use serde::Serialize;
use serde_json::Value;

use crate::broker::{
    AllowPolicy, AuthStrategy, Broker, BrokerConfig, Capability, CapabilityAdvancedPolicy,
    CredentialInput, Header, MultipartFileSerde, PlannedRequest, ProxyEnvelope,
    ProxyEnvelopeRequest, ProxyTokenMintRequest, RequestAuth, RequestBodyMode, SecretMaterial,
    UpstreamResponse,
};
use crate::broker_store::{BrokerStore, StoredCapabilityPolicy, StoredCredential};
use crate::capabilities::{CapabilityBinding, CapabilityScope, CapabilityStore};
use crate::cli::{
    AuthKind, CapabilitiesCommand, CapabilityCommand, CapabilityPolicyCommand, Cli, Command,
    CredentialCommand, InvokeArgs, OauthCommand, ProviderKind, ScopeKind, SecretsCommand,
};
use crate::vault::{
    read_audit_events, read_audit_events_before, SecretRef, SecretScope, VaultProviderConfig,
    VaultRuntime,
};

pub fn run(cli: Cli) -> Result<(), String> {
    let vault = VaultRuntime::discover();
    vault.load().map_err(|e| e.to_string())?;

    match cli.command {
        Command::Status => run_status(&vault),
        Command::Init {
            provider,
            env_var,
            file_path,
            keychain_service,
            keychain_account,
            passphrase,
        } => run_init(
            &vault,
            provider,
            env_var,
            file_path,
            keychain_service,
            keychain_account,
            passphrase,
        ),
        Command::Unlock { passphrase } => {
            let status = vault.unlock(&passphrase).map_err(|e| e.to_string())?;
            print_json(&status)
        }
        Command::Lock => {
            let status = vault.lock().map_err(|e| e.to_string())?;
            print_json(&status)
        }
        Command::RotateMaster {
            new_key,
            new_passphrase,
        } => {
            let status = vault
                .rotate_master_key(new_key.as_deref(), new_passphrase.as_deref())
                .map_err(|e| e.to_string())?;
            print_json(&status)
        }
        Command::Audit {
            limit,
            before_ts_ms,
        } => {
            let events = if let Some(before) = before_ts_ms.filter(|v| *v > 0) {
                read_audit_events_before(&vault.paths().audit_dir(), limit, Some(before))?
            } else {
                read_audit_events(&vault.paths().audit_dir(), limit)?
            };
            print_json(&events)
        }
        Command::Secrets { command } => run_secrets(&vault, command),
        Command::Capabilities { command } => run_capabilities(&vault, command),
        Command::Oauth { command } => run_oauth(command),
        Command::Credential { command } => run_credential(&vault, command),
        Command::Capability { command } => run_capability(&vault, command),
        Command::Invoke { args } => run_invoke(&vault, args),
        Command::Resolve { secret_ref, raw } => {
            let value = vault
                .resolve_secret_ref(&secret_ref, Some("vault.resolve"), Some("aivault-cli"))
                .map_err(|e| e.to_string())?;
            print_resolved_value(&secret_ref, value, raw)
        }
        Command::ResolveTeam {
            secret_ref,
            workspace_id,
            team,
            raw,
        } => {
            let value = vault
                .resolve_secret_ref_for_team(
                    &secret_ref,
                    &workspace_id,
                    &team,
                    Some("vault.resolve_team"),
                    Some("aivault-cli"),
                )
                .map_err(|e| e.to_string())?;
            print_resolved_value(&secret_ref, value, raw)
        }
    }
}

fn run_status(vault: &VaultRuntime) -> Result<(), String> {
    let payload = serde_json::json!({
        "status": vault.status(),
        "paths": {
            "rootDir": vault.paths().root_dir().display().to_string(),
            "configPath": vault.paths().config_path().display().to_string(),
            "secretsDir": vault.paths().secrets_dir().display().to_string(),
            "auditDir": vault.paths().audit_dir().display().to_string(),
            "capabilitiesPath": vault.paths().root_dir().join("capabilities.json").display().to_string()
        }
    });
    print_json(&payload)
}

fn run_init(
    vault: &VaultRuntime,
    provider: ProviderKind,
    env_var: Option<String>,
    file_path: Option<String>,
    keychain_service: Option<String>,
    keychain_account: Option<String>,
    passphrase: Option<String>,
) -> Result<(), String> {
    let status = match provider {
        ProviderKind::Passphrase => {
            let passphrase = passphrase
                .as_deref()
                .ok_or_else(|| "--passphrase is required for --provider passphrase".to_string())?;
            vault.init_passphrase(passphrase)
        }
        ProviderKind::MacosKeychain => vault.init(VaultProviderConfig::MacosKeychain {
            service: keychain_service.unwrap_or_else(|| "aivault".to_string()),
            account: keychain_account.unwrap_or_else(|| "kek".to_string()),
        }),
        ProviderKind::Env => vault.init(VaultProviderConfig::Env {
            env_var: env_var.unwrap_or_else(|| "AIVAULT_KEY".to_string()),
        }),
        ProviderKind::File => vault.init(VaultProviderConfig::File {
            path: file_path.unwrap_or_else(|| {
                vault
                    .paths()
                    .root_dir()
                    .join("kek.key")
                    .display()
                    .to_string()
            }),
        }),
    }
    .map_err(|e| e.to_string())?;

    print_json(&status)
}

fn run_secrets(vault: &VaultRuntime, command: SecretsCommand) -> Result<(), String> {
    match command {
        SecretsCommand::List {
            scope,
            workspace_id,
            team,
        } => {
            let mut list = vault.list_secrets().map_err(|e| e.to_string())?;
            if let Some(scope_kind) = scope {
                list.retain(|meta| {
                    scope_matches_secret(
                        &meta.scope,
                        &scope_kind,
                        workspace_id.as_deref(),
                        team.as_deref(),
                    )
                });
            }
            print_json(&list)
        }
        SecretsCommand::Create {
            name,
            value,
            scope,
            workspace_id,
            team,
            alias,
        } => {
            let scope = parse_secret_scope(scope, workspace_id.as_deref(), team.as_deref())?;
            let meta = vault
                .create_secret(&name, value.as_bytes(), scope, alias)
                .map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::Update {
            id,
            name,
            alias,
            clear_aliases,
        } => {
            let aliases = if clear_aliases {
                Some(Vec::new())
            } else if alias.is_empty() {
                None
            } else {
                Some(alias)
            };
            let meta = vault
                .update_secret_meta(&id, name, aliases)
                .map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::Rotate { id, value } => {
            let meta = vault
                .rotate_secret_value(&id, value.as_bytes())
                .map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::Delete { id } => {
            let meta = vault.revoke_secret(&id).map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::AttachTeam {
            id,
            workspace_id,
            team,
        } => {
            let meta = vault
                .attach_secret_to_team(&id, &workspace_id, &team)
                .map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::DetachTeam {
            id,
            workspace_id,
            team,
        } => {
            let meta = vault
                .detach_secret_from_team(&id, &workspace_id, &team)
                .map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::Import {
            entry,
            scope,
            workspace_id,
            team,
        } => {
            let scope = parse_secret_scope(scope, workspace_id.as_deref(), team.as_deref())?;
            let mut entries = BTreeMap::new();
            for raw in entry {
                let Some((key, value)) = raw.split_once('=') else {
                    return Err(format!("invalid --entry '{}'; expected KEY=VALUE", raw));
                };
                let key = key.trim();
                if key.is_empty() {
                    return Err("entry key cannot be empty".to_string());
                }
                entries.insert(key.to_string(), value.to_string());
            }

            let existing = vault.list_secrets().map_err(|e| e.to_string())?;
            let mut by_name: HashMap<String, String> = HashMap::new();
            for meta in existing {
                if meta.scope == scope {
                    by_name.insert(meta.name.clone(), meta.secret_id.clone());
                }
            }

            let mut created = Vec::new();
            let mut rotated = Vec::new();
            let mut skipped = Vec::new();

            for (key, value) in entries {
                if value.trim().is_empty() {
                    skipped.push(key);
                    continue;
                }

                if let Some(secret_id) = by_name.get(&key).cloned() {
                    if vault
                        .rotate_secret_value(&secret_id, value.as_bytes())
                        .is_ok()
                    {
                        rotated.push(key);
                    } else {
                        skipped.push(key);
                    }
                    continue;
                }

                if vault
                    .create_secret(&key, value.as_bytes(), scope.clone(), Vec::new())
                    .is_ok()
                {
                    created.push(key);
                } else {
                    skipped.push(key);
                }
            }

            print_json(&serde_json::json!({
                "created": created,
                "rotated": rotated,
                "skipped": skipped
            }))
        }
    }
}

fn run_capabilities(vault: &VaultRuntime, command: CapabilitiesCommand) -> Result<(), String> {
    let mut store = CapabilityStore::open_under(vault.paths().root_dir())?;

    match command {
        CapabilitiesCommand::List {
            capability,
            scope,
            workspace_id,
            team,
            consumer,
        } => {
            let scope_filter = if let Some(scope) = scope {
                Some(parse_capability_scope(
                    scope,
                    workspace_id.as_deref(),
                    team.as_deref(),
                )?)
            } else {
                None
            };

            let mut list = store.list();
            if let Some(capability) = capability {
                list.retain(|binding| binding.capability == capability.trim());
            }
            if let Some(scope_filter) = scope_filter {
                list.retain(|binding| binding.scope == scope_filter);
            }
            if let Some(consumer) = consumer.map(|v| v.trim().to_string()) {
                if !consumer.is_empty() {
                    list.retain(|binding| binding.consumer.as_deref() == Some(consumer.as_str()));
                }
            }
            print_json(&list)
        }
        CapabilitiesCommand::Bind {
            capability,
            secret_ref,
            scope,
            workspace_id,
            team,
            consumer,
        } => {
            let parsed = SecretRef::parse(&secret_ref)?;
            vault
                .get_secret_meta(&parsed.secret_id)
                .map_err(|e| format!("secret does not exist: {}", e))?;

            let scope = parse_capability_scope(scope, workspace_id.as_deref(), team.as_deref())?;
            let binding = store.upsert(&capability, &secret_ref, scope, consumer)?;
            store.save()?;
            print_json(&binding)
        }
        CapabilitiesCommand::Unbind {
            capability,
            scope,
            workspace_id,
            team,
            consumer,
        } => {
            let scope = parse_capability_scope(scope, workspace_id.as_deref(), team.as_deref())?;
            let removed = store.remove(&capability, &scope, consumer.as_deref());
            if removed {
                store.save()?;
            }
            print_json(&serde_json::json!({
                "removed": removed,
                "path": store.path().display().to_string()
            }))
        }
        CapabilitiesCommand::Resolve {
            capability,
            workspace_id,
            team,
            consumer,
            raw,
        } => {
            let binding = store
                .resolve(
                    &capability,
                    workspace_id.as_deref(),
                    team.as_deref(),
                    consumer.as_deref(),
                )
                .ok_or_else(|| format!("no binding found for capability '{}'", capability))?;

            let value =
                resolve_binding_value(vault, &binding, workspace_id.as_deref(), team.as_deref())?;

            if raw {
                let text = String::from_utf8(value)
                    .map_err(|_| "secret is not valid UTF-8; use non-raw mode".to_string())?;
                println!("{}", text);
                return Ok(());
            }

            print_json(&serde_json::json!({
                "binding": binding,
                "valueB64": base64::engine::general_purpose::STANDARD.encode(value)
            }))
        }
    }
}

fn run_oauth(command: OauthCommand) -> Result<(), String> {
    match command {
        OauthCommand::Setup {
            provider,
            auth_url,
            client_id,
            redirect_uri,
            scope,
            state,
        } => {
            let plan = build_oauth_setup_plan(
                &provider,
                &auth_url,
                &client_id,
                &redirect_uri,
                &scope,
                state.as_deref(),
            )?;
            print_json(&plan)
        }
    }
}

fn run_credential(vault: &VaultRuntime, command: CredentialCommand) -> Result<(), String> {
    let mut store = BrokerStore::open_under(vault.paths().root_dir())?;

    match command {
        CredentialCommand::Create {
            id,
            provider,
            secret_ref,
            auth,
            host,
            header_name,
            value_template,
            query_param,
            grant_type,
            token_endpoint,
            scope,
            aws_service,
            aws_region,
            hmac_algorithm,
        } => {
            let id = id.trim().to_string();
            if id.is_empty() {
                return Err("credential id is required".to_string());
            }
            if store
                .credentials()
                .iter()
                .any(|credential| credential.id == id)
            {
                return Err(format!("credential '{}' already exists", id));
            }

            let auth = build_auth_strategy(
                auth,
                AuthBuildOptions {
                    header_name,
                    value_template,
                    query_param,
                    grant_type,
                    token_endpoint,
                    scope,
                    aws_service,
                    aws_region,
                    hmac_algorithm,
                },
            );
            if host.is_empty() {
                return Err("at least one --host is required".to_string());
            }
            let provider = provider.trim().to_string();
            if provider.is_empty() {
                return Err("credential provider is required".to_string());
            }
            let parsed = SecretRef::parse(&secret_ref)?;
            vault
                .get_secret_meta(&parsed.secret_id)
                .map_err(|e| format!("secret does not exist: {}", e))?;

            let credential = StoredCredential {
                id,
                provider,
                auth,
                hosts: host,
                secret_ref,
            };
            store.upsert_credential(credential.clone());
            store.save()?;
            print_json(&credential)
        }
        CredentialCommand::List => {
            let payload = serde_json::json!({
                "credentials": store.credentials(),
                "path": vault.paths().root_dir().join("broker.json").display().to_string()
            });
            print_json(&payload)
        }
        CredentialCommand::Delete { id } => {
            let removed = store.remove_credential(id.trim());
            if removed {
                store.save()?;
            }
            print_json(&serde_json::json!({
                "removed": removed,
                "id": id.trim(),
            }))
        }
    }
}

fn run_capability(vault: &VaultRuntime, command: CapabilityCommand) -> Result<(), String> {
    let mut store = BrokerStore::open_under(vault.paths().root_dir())?;

    match command {
        CapabilityCommand::Create {
            id,
            provider,
            credential,
            method,
            path,
            host,
        } => {
            let id = id.trim().to_string();
            if id.is_empty() {
                return Err("capability id is required".to_string());
            }
            if store
                .capabilities()
                .iter()
                .any(|capability| capability.id == id)
            {
                return Err(format!("capability '{}' already exists", id));
            }
            if method.is_empty() {
                return Err("at least one --method is required".to_string());
            }
            if path.is_empty() {
                return Err("at least one --path is required".to_string());
            }

            let credential_id = credential
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty());
            let provider = match provider {
                Some(provider) => provider,
                None => {
                    let credential_id = credential_id.ok_or_else(|| {
                        "--provider or --credential is required for capability create".to_string()
                    })?;
                    store
                        .credentials()
                        .iter()
                        .find(|c| c.id == credential_id)
                        .map(|c| c.provider.clone())
                        .ok_or_else(|| format!("credential '{}' not found", credential_id))?
                }
            };

            let hosts = if host.is_empty() {
                if let Some(credential_id) = credential_id {
                    store
                        .credentials()
                        .iter()
                        .find(|c| c.id == credential_id)
                        .map(|c| c.hosts.clone())
                        .ok_or_else(|| format!("credential '{}' not found", credential_id))?
                } else {
                    return Err(
                        "at least one --host is required when --credential is not provided"
                            .to_string(),
                    );
                }
            } else {
                host
            };

            let capability = Capability {
                id,
                provider: provider.trim().to_string(),
                allow: AllowPolicy {
                    hosts,
                    methods: method,
                    path_prefixes: path,
                },
            };
            if capability.id.is_empty() || capability.provider.is_empty() {
                return Err("capability id and provider are required".to_string());
            }
            store.upsert_capability(capability.clone());
            store.save()?;
            print_json(&capability)
        }
        CapabilityCommand::List => {
            let payload = serde_json::json!({
                "capabilities": store.capabilities(),
                "policies": store.policies(),
                "path": vault.paths().root_dir().join("broker.json").display().to_string()
            });
            print_json(&payload)
        }
        CapabilityCommand::Delete { id } => {
            let id = id.trim();
            let removed_capability = store.remove_capability(id);
            let removed_policy = store.remove_policy(id);
            if removed_capability || removed_policy {
                store.save()?;
            }
            print_json(&serde_json::json!({
                "removedCapability": removed_capability,
                "removedPolicy": removed_policy,
                "id": id,
            }))
        }
        CapabilityCommand::Policy { command } => match command {
            CapabilityPolicyCommand::Set {
                capability,
                rate_limit_per_minute,
                max_request_body_bytes,
                max_response_body_bytes,
                response_block,
            } => {
                let capability = capability.trim().to_string();
                if capability.is_empty() {
                    return Err("--capability is required".to_string());
                }
                if store.find_capability(&capability).is_none() {
                    return Err(format!("capability '{}' not found", capability));
                }
                let policy = StoredCapabilityPolicy {
                    capability_id: capability.clone(),
                    policy: CapabilityAdvancedPolicy {
                        rate_limit_per_minute,
                        max_request_body_bytes,
                        max_response_body_bytes,
                        response_body_blocklist: response_block,
                    },
                };
                store.upsert_policy(policy.clone());
                store.save()?;
                print_json(&policy)
            }
        },
        CapabilityCommand::Describe { id } => print_capability_call_args(&store, &id),
        CapabilityCommand::Invoke { args } => invoke_with_store(vault, &store, args),
    }
}

fn run_invoke(vault: &VaultRuntime, args: InvokeArgs) -> Result<(), String> {
    let store = BrokerStore::open_under(vault.paths().root_dir())?;
    invoke_with_store(vault, &store, args)
}

fn invoke_with_store(
    vault: &VaultRuntime,
    store: &BrokerStore,
    args: InvokeArgs,
) -> Result<(), String> {
    let capability = store
        .find_capability(args.id.trim())
        .ok_or_else(|| format!("capability '{}' not found", args.id.trim()))?;
    let envelope = build_capability_call_envelope(capability, args.clone())?;
    let client_ip: IpAddr = args
        .client_ip
        .parse()
        .map_err(|_| "invalid --client-ip".to_string())?;
    let response = run_capability_envelope(vault, store, envelope, client_ip)?;
    print_json(&response)
}

fn print_capability_call_args(store: &BrokerStore, id: &str) -> Result<(), String> {
    let id = id.trim();
    let capability = store
        .find_capability(id)
        .ok_or_else(|| format!("capability '{}' not found", id))?;

    let default_method = if capability.allow.methods.len() == 1 {
        Some(capability.allow.methods[0].clone())
    } else {
        None
    };
    let default_path = if capability.allow.path_prefixes.len() == 1 {
        Some(capability.allow.path_prefixes[0].clone())
    } else {
        None
    };

    let mut required = Vec::new();
    if default_method.is_none() {
        required.push("--method");
    }
    if default_path.is_none() {
        required.push("--path");
    }

    let payload = serde_json::json!({
        "capability": capability.id,
        "provider": capability.provider,
        "allowed": {
            "hosts": capability.allow.hosts,
            "methods": capability.allow.methods,
            "pathPrefixes": capability.allow.path_prefixes
        },
        "call": {
            "requiredFlagsWhenNoRequestPayload": required,
            "defaults": {
                "method": default_method,
                "path": default_path
            },
            "optionalFlags": [
                "--credential",
                "--header NAME=VALUE",
                "--body TEXT",
                "--body-file-path PATH",
                "--multipart-field KEY=VALUE",
                "--multipart-file FIELD=PATH",
                "--client-ip IP"
            ],
            "payloadModes": [
                "--request '<json request or envelope>'",
                "--request-file <path>"
            ]
        }
    });
    print_json(&payload)
}

fn build_capability_call_envelope(
    capability: &Capability,
    args: InvokeArgs,
) -> Result<ProxyEnvelope, String> {
    let InvokeArgs {
        id: _,
        request,
        request_file,
        method,
        path,
        header,
        body,
        body_file_path,
        multipart_field,
        multipart_file,
        credential,
        client_ip: _,
    } = args;
    let has_payload = request.is_some() || request_file.is_some();
    let has_manual_fields = method.is_some()
        || path.is_some()
        || !header.is_empty()
        || body.is_some()
        || body_file_path.is_some()
        || !multipart_field.is_empty()
        || !multipart_file.is_empty();

    if has_payload {
        if request.is_some() && request_file.is_some() {
            return Err("provide only one of --request or --request-file".to_string());
        }
        if has_manual_fields {
            return Err(
                "do not mix --request/--request-file with manual request flags".to_string(),
            );
        }

        let raw = if let Some(raw) = request {
            raw
        } else if let Some(path) = request_file {
            std::fs::read_to_string(path).map_err(|e| e.to_string())?
        } else {
            return Err("request payload is required".to_string());
        };

        let mut envelope = if let Ok(parsed) = Broker::parse_envelope(&raw) {
            parsed
        } else {
            let request = serde_json::from_str::<ProxyEnvelopeRequest>(&raw)
                .map_err(|e| format!("invalid request payload JSON: {}", e))?;
            ProxyEnvelope {
                capability: capability.id.clone(),
                credential: None,
                request,
            }
        };

        if envelope.capability.trim().is_empty() {
            envelope.capability = capability.id.clone();
        } else if envelope.capability != capability.id {
            return Err(format!(
                "request capability '{}' does not match command capability '{}'",
                envelope.capability, capability.id
            ));
        }

        if let Some(credential) = credential.map(|v| v.trim().to_string()) {
            if credential.is_empty() {
                return Err("--credential cannot be empty".to_string());
            }
            if envelope.credential.is_some() {
                return Err("credential provided in both payload and --credential".to_string());
            }
            envelope.credential = Some(credential);
        }

        return Ok(envelope);
    }

    let method = resolve_capability_call_method(method, &capability.allow.methods)?;
    let path = resolve_capability_call_path(path, &capability.allow.path_prefixes)?;
    let headers = parse_headers(header)?;
    let multipart = parse_multipart_fields(multipart_field)?;
    let files = parse_multipart_files(multipart_file)?;

    let body_modes = [
        body.is_some(),
        body_file_path.is_some(),
        multipart.is_some() || !files.is_empty(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if body_modes > 1 {
        return Err(
            "only one of --body, --body-file-path, or multipart flags is allowed".to_string(),
        );
    }

    let credential = credential
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    Ok(ProxyEnvelope {
        capability: capability.id.clone(),
        credential,
        request: ProxyEnvelopeRequest {
            method,
            path,
            headers,
            body,
            multipart,
            multipart_files: files,
            body_file_path,
            url: None,
        },
    })
}

fn resolve_capability_call_method(
    provided: Option<String>,
    allowed: &[String],
) -> Result<String, String> {
    if let Some(method) = provided {
        let method = method.trim().to_string();
        if method.is_empty() {
            return Err("--method cannot be empty".to_string());
        }
        return Ok(method);
    }
    if allowed.len() == 1 {
        return Ok(allowed[0].clone());
    }
    Err(format!(
        "--method is required because capability allows multiple methods: {}",
        allowed.join(", ")
    ))
}

fn resolve_capability_call_path(
    provided: Option<String>,
    allowed: &[String],
) -> Result<String, String> {
    if let Some(path) = provided {
        let path = path.trim().to_string();
        if path.is_empty() {
            return Err("--path cannot be empty".to_string());
        }
        return Ok(path);
    }
    if allowed.len() == 1 {
        return Ok(allowed[0].clone());
    }
    Err(format!(
        "--path is required because capability allows multiple path prefixes: {}",
        allowed.join(", ")
    ))
}

fn parse_headers(raw_headers: Vec<String>) -> Result<Vec<Header>, String> {
    let mut headers = Vec::new();
    for raw in raw_headers {
        let (name, value) = parse_key_value_pair(&raw, "--header")?;
        headers.push(Header { name, value });
    }
    Ok(headers)
}

fn parse_multipart_fields(
    raw_fields: Vec<String>,
) -> Result<Option<HashMap<String, String>>, String> {
    if raw_fields.is_empty() {
        return Ok(None);
    }
    let mut fields = HashMap::new();
    for raw in raw_fields {
        let (key, value) = parse_key_value_pair(&raw, "--multipart-field")?;
        if fields.insert(key.clone(), value).is_some() {
            return Err(format!("duplicate multipart field '{}'", key));
        }
    }
    Ok(Some(fields))
}

fn parse_multipart_files(raw_files: Vec<String>) -> Result<Vec<MultipartFileSerde>, String> {
    let mut files = Vec::new();
    for raw in raw_files {
        let (field, path) = parse_key_value_pair(&raw, "--multipart-file")?;
        files.push(MultipartFileSerde { field, path });
    }
    Ok(files)
}

fn parse_key_value_pair(raw: &str, flag: &str) -> Result<(String, String), String> {
    let Some((key, value)) = raw.split_once('=') else {
        return Err(format!("invalid {} '{}'; expected KEY=VALUE", flag, raw));
    };
    let key = key.trim();
    if key.is_empty() {
        return Err(format!("invalid {} '{}'; key cannot be empty", flag, raw));
    }
    Ok((key.to_string(), value.to_string()))
}

fn run_capability_envelope(
    vault: &VaultRuntime,
    store: &BrokerStore,
    envelope: ProxyEnvelope,
    client_ip: IpAddr,
) -> Result<Value, String> {
    let mut broker = load_runtime_broker(vault, store)?;
    let token = broker
        .mint_proxy_token(
            &RequestAuth::Operator("operator-cli".to_string()),
            ProxyTokenMintRequest {
                capabilities: vec![envelope.capability.clone()],
                credential: envelope.credential.clone(),
                ttl_ms: 60_000,
                context: HashMap::from([("source".to_string(), "aivault-cli".to_string())]),
            },
        )
        .map_err(|e| e.to_string())?;

    let planned = broker
        .execute_envelope(&RequestAuth::Proxy(token.token), envelope, client_ip)
        .map_err(|e| e.to_string())?;
    execute_planned_http_request(&broker, &planned)
}

struct AuthBuildOptions {
    header_name: Option<String>,
    value_template: Option<String>,
    query_param: Option<String>,
    grant_type: Option<String>,
    token_endpoint: Option<String>,
    scope: Vec<String>,
    aws_service: Option<String>,
    aws_region: Option<String>,
    hmac_algorithm: Option<String>,
}

fn build_auth_strategy(auth: AuthKind, options: AuthBuildOptions) -> AuthStrategy {
    match auth {
        AuthKind::Header => AuthStrategy::Header {
            header_name: options
                .header_name
                .unwrap_or_else(|| "authorization".to_string()),
            value_template: options
                .value_template
                .unwrap_or_else(|| "Bearer {{secret}}".to_string()),
        },
        AuthKind::Query => AuthStrategy::Query {
            param_name: options.query_param.unwrap_or_else(|| "api_key".to_string()),
        },
        AuthKind::Basic => AuthStrategy::Basic,
        AuthKind::OAuth2 => AuthStrategy::OAuth2 {
            grant_type: options
                .grant_type
                .unwrap_or_else(|| "refresh_token".to_string()),
            token_endpoint: options
                .token_endpoint
                .unwrap_or_else(|| "https://oauth.example/token".to_string()),
            scopes: options.scope,
        },
        AuthKind::AwsSigv4 => AuthStrategy::AwsSigV4 {
            service: options.aws_service.unwrap_or_else(|| "s3".to_string()),
            region: options
                .aws_region
                .unwrap_or_else(|| "us-east-1".to_string()),
        },
        AuthKind::Hmac => AuthStrategy::Hmac {
            algorithm: options
                .hmac_algorithm
                .unwrap_or_else(|| "sha256".to_string()),
            header_name: options
                .header_name
                .unwrap_or_else(|| "x-signature".to_string()),
            value_template: options
                .value_template
                .unwrap_or_else(|| "sha256={{signature}}".to_string()),
        },
        AuthKind::Mtls => AuthStrategy::Mtls,
    }
}

fn load_runtime_broker(vault: &VaultRuntime, store: &BrokerStore) -> Result<Broker, String> {
    let mut cfg = BrokerConfig::default();
    if env_flag_true("AIVAULT_DEV_ALLOW_HTTP_LOCAL") {
        cfg.allow_http_local_extension = true;
    }
    if env_flag_true("AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS") {
        cfg.allow_non_default_ports_extension = true;
    }
    if env_flag_true("AIVAULT_DEV_ALLOW_REMOTE_CLIENTS") {
        cfg.allow_remote_clients = true;
    }

    let mut broker = Broker::new(cfg, None);
    let operator = RequestAuth::Operator("operator-cli".to_string());

    for stored in store.credentials() {
        let secret = vault
            .resolve_secret_ref(
                &stored.secret_ref,
                Some("broker.credential.load"),
                Some("aivault-cli"),
            )
            .map_err(|e| e.to_string())?;
        let secret = secret_material_from_bytes(&stored.auth, secret)?;
        broker
            .create_credential(
                &operator,
                CredentialInput {
                    id: stored.id.clone(),
                    provider: stored.provider.clone(),
                    auth: Some(stored.auth.clone()),
                    hosts: Some(stored.hosts.clone()),
                },
                secret,
            )
            .map_err(|e| e.to_string())?;
    }

    for capability in store.capabilities() {
        broker
            .upsert_capability(&operator, capability.clone())
            .map_err(|e| e.to_string())?;
    }
    for policy in store.policies() {
        broker
            .set_capability_advanced_policy(&operator, &policy.capability_id, policy.policy.clone())
            .map_err(|e| e.to_string())?;
    }

    Ok(broker)
}

fn env_flag_true(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn secret_material_from_bytes(auth: &AuthStrategy, raw: Vec<u8>) -> Result<SecretMaterial, String> {
    #[derive(serde::Deserialize)]
    struct BasicSecret {
        username: String,
        password: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OAuth2Secret {
        client_id: String,
        client_secret: String,
        #[serde(default)]
        refresh_token: String,
        #[serde(default)]
        access_token: Option<String>,
        #[serde(default)]
        access_token_expires_at_ms: Option<i64>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AwsSecret {
        access_key_id: String,
        secret_access_key: String,
        #[serde(default)]
        session_token: Option<String>,
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MtlsSecret {
        cert_pem: String,
        key_pem: String,
    }

    let as_utf8 = || String::from_utf8(raw.clone()).map_err(|_| "secret must be utf-8".to_string());

    match auth {
        AuthStrategy::Header { .. } | AuthStrategy::Query { .. } => {
            Ok(SecretMaterial::String(as_utf8()?))
        }
        AuthStrategy::Basic => {
            let parsed: BasicSecret = serde_json::from_slice(&raw)
                .map_err(|_| "basic secret must be JSON with username/password".to_string())?;
            Ok(SecretMaterial::Basic {
                username: parsed.username,
                password: parsed.password,
            })
        }
        AuthStrategy::OAuth2 { .. } => {
            let parsed: OAuth2Secret = serde_json::from_slice(&raw).map_err(|_| {
                "oauth2 secret must be JSON with clientId/clientSecret/refreshToken".to_string()
            })?;
            Ok(SecretMaterial::OAuth2 {
                client_id: parsed.client_id,
                client_secret: parsed.client_secret,
                refresh_token: parsed.refresh_token,
                access_token: parsed.access_token,
                access_token_expires_at_ms: parsed.access_token_expires_at_ms,
            })
        }
        AuthStrategy::AwsSigV4 { .. } => {
            let parsed: AwsSecret = serde_json::from_slice(&raw).map_err(|_| {
                "aws secret must be JSON with accessKeyId/secretAccessKey".to_string()
            })?;
            Ok(SecretMaterial::Aws {
                access_key_id: parsed.access_key_id,
                secret_access_key: parsed.secret_access_key,
                session_token: parsed.session_token,
            })
        }
        AuthStrategy::Hmac { .. } => Ok(SecretMaterial::Hmac { secret: as_utf8()? }),
        AuthStrategy::Mtls => {
            let parsed: MtlsSecret = serde_json::from_slice(&raw)
                .map_err(|_| "mtls secret must be JSON with certPem/keyPem".to_string())?;
            Ok(SecretMaterial::Mtls {
                cert_pem: parsed.cert_pem,
                key_pem: parsed.key_pem,
            })
        }
    }
}

fn execute_planned_http_request(
    broker: &Broker,
    planned: &PlannedRequest,
) -> Result<Value, String> {
    let mut url = reqwest::Url::parse(&format!(
        "{}://{}{}",
        planned.scheme, planned.host, planned.path
    ))
    .map_err(|e| e.to_string())?;
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in &planned.query {
            qp.append_pair(k, v);
        }
    }

    let method =
        reqwest::Method::from_bytes(planned.method.as_bytes()).map_err(|e| e.to_string())?;
    let client = build_http_client_with_dev_overrides()?;

    let mut req = client.request(method, url.clone());
    let is_multipart = matches!(planned.body_mode, RequestBodyMode::Multipart { .. });
    for header in &planned.headers {
        if is_multipart && header.name.eq_ignore_ascii_case("content-type") {
            continue;
        }
        req = req.header(header.name.as_str(), header.value.as_str());
    }

    req = match &planned.body_mode {
        RequestBodyMode::Empty => req,
        RequestBodyMode::Text(text) => req.body(text.clone()),
        RequestBodyMode::BodyFilePath(path) => {
            let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
            req.body(bytes)
        }
        RequestBodyMode::Multipart { fields, files } => {
            let mut form = Form::new();
            for (k, v) in fields {
                form = form.text(k.clone(), v.clone());
            }
            for file in files {
                form = form
                    .file(file.field.clone(), file.path.clone())
                    .map_err(|e| e.to_string())?;
            }
            req.multipart(form)
        }
    };

    let response = req.send().map_err(|e| format_reqwest_error(&e))?;
    let status = response.status().as_u16();
    let headers: Vec<Header> = response
        .headers()
        .iter()
        .map(|(k, v)| Header {
            name: k.as_str().to_string(),
            value: v.to_str().unwrap_or_default().to_string(),
        })
        .collect();
    let body = response.bytes().map_err(|e| e.to_string())?.to_vec();

    let forwarded = broker
        .forward_response_for_capability(
            &planned.capability,
            UpstreamResponse {
                status,
                headers,
                body_chunks: vec![body],
            },
        )
        .map_err(|e| e.to_string())?;

    let body_raw = forwarded.body_chunks.concat();
    let body_utf8 = String::from_utf8(body_raw.clone()).ok();
    Ok(serde_json::json!({
        "planned": {
            "capability": planned.capability,
            "credential": planned.credential,
            "method": planned.method,
            "url": url.to_string()
        },
        "response": {
            "status": forwarded.status,
            "headers": forwarded.headers,
            "bodyUtf8": body_utf8,
            "bodyB64": base64::engine::general_purpose::STANDARD.encode(body_raw)
        }
    }))
}

fn format_reqwest_error(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut current: Option<&(dyn std::error::Error + 'static)> = error.source();
    while let Some(source) = current {
        message.push_str(": ");
        message.push_str(&source.to_string());
        current = source.source();
    }
    message
}

fn build_http_client_with_dev_overrides() -> Result<Client, String> {
    let mut builder = Client::builder().redirect(RedirectPolicy::none());
    if env_flag_true("AIVAULT_DEV_HTTP1_ONLY") {
        builder = builder.http1_only();
    }

    if let Some(cert_path) = std::env::var("AIVAULT_DEV_CA_CERT_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        let pem = std::fs::read(&cert_path).map_err(|err| {
            format!(
                "failed reading AIVAULT_DEV_CA_CERT_PATH '{}': {}",
                cert_path, err
            )
        })?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|err| {
            format!(
                "invalid PEM certificate in AIVAULT_DEV_CA_CERT_PATH '{}': {}",
                cert_path, err
            )
        })?;
        builder = builder.add_root_certificate(cert);
    }

    if let Some(overrides_raw) = std::env::var("AIVAULT_DEV_RESOLVE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        for pair in overrides_raw.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let Some((domain, addr_raw)) = pair.split_once('=') else {
                return Err(format!(
                    "invalid AIVAULT_DEV_RESOLVE entry '{}'; expected host=ip:port",
                    pair
                ));
            };
            let domain = domain.trim();
            if domain.is_empty() {
                return Err("invalid AIVAULT_DEV_RESOLVE entry with empty host".to_string());
            }
            let addr: SocketAddr = addr_raw.trim().parse().map_err(|_| {
                format!(
                    "invalid socket address '{}' in AIVAULT_DEV_RESOLVE entry '{}'",
                    addr_raw, pair
                )
            })?;
            builder = builder.resolve(domain, addr);
        }
    }

    builder.build().map_err(|err| err.to_string())
}

fn build_oauth_setup_plan(
    provider: &str,
    auth_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: Option<&str>,
) -> Result<Value, String> {
    let provider = provider.trim();
    let auth_url = auth_url.trim();
    let client_id = client_id.trim();
    let redirect_uri = redirect_uri.trim();
    if provider.is_empty() || auth_url.is_empty() || client_id.is_empty() || redirect_uri.is_empty()
    {
        return Err("provider, auth_url, client_id, and redirect_uri are required".to_string());
    }

    let mut params = vec![
        ("response_type", "code".to_string()),
        ("client_id", client_id.to_string()),
        ("redirect_uri", redirect_uri.to_string()),
    ];
    if !scopes.is_empty() {
        let scopes = scopes
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !scopes.is_empty() {
            params.push(("scope", scopes));
        }
    }
    if let Some(state) = state.map(str::trim).filter(|v| !v.is_empty()) {
        params.push(("state", state.to_string()));
    }
    let encoded = params
        .into_iter()
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(&v)))
        .collect::<Vec<_>>()
        .join("&");
    let separator = if auth_url.contains('?') { "&" } else { "?" };
    let consent_url = format!("{auth_url}{separator}{encoded}");

    Ok(serde_json::json!({
        "provider": provider,
        "consentUrl": consent_url,
        "exchangeOutsideBroker": true,
        "notes": [
            "Open consentUrl in a browser and complete user authorization outside the broker boundary.",
            "Exchange the returned authorization code for tokens using provider tooling or your runtime.",
            "Store resulting refresh/client secrets in Vault; broker runtime only handles refresh/client_credentials grants."
        ]
    }))
}

fn pct_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        let ch = *byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn resolve_binding_value(
    vault: &VaultRuntime,
    binding: &CapabilityBinding,
    workspace_id: Option<&str>,
    team: Option<&str>,
) -> Result<Vec<u8>, String> {
    if let (Some(workspace_id), Some(team)) = (workspace_id, team) {
        return vault
            .resolve_secret_ref_for_team(
                &binding.secret_ref,
                workspace_id,
                team,
                Some(&binding.capability),
                binding.consumer.as_deref().or(Some("aivault-cli")),
            )
            .map_err(|e| e.to_string());
    }

    vault
        .resolve_secret_ref(
            &binding.secret_ref,
            Some(&binding.capability),
            binding.consumer.as_deref().or(Some("aivault-cli")),
        )
        .map_err(|e| e.to_string())
}

fn parse_secret_scope(
    scope: ScopeKind,
    workspace_id: Option<&str>,
    team: Option<&str>,
) -> Result<SecretScope, String> {
    match scope {
        ScopeKind::Global => Ok(SecretScope::Global),
        ScopeKind::Workspace => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            Ok(SecretScope::Workspace {
                workspace_id: workspace_id.to_string(),
            })
        }
        ScopeKind::Team => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            let team = required_arg("team", team)?;
            Ok(SecretScope::Team {
                workspace_id: workspace_id.to_string(),
                team: team.to_string(),
            })
        }
    }
}

fn parse_capability_scope(
    scope: ScopeKind,
    workspace_id: Option<&str>,
    team: Option<&str>,
) -> Result<CapabilityScope, String> {
    match scope {
        ScopeKind::Global => Ok(CapabilityScope::Global),
        ScopeKind::Workspace => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            Ok(CapabilityScope::Workspace {
                workspace_id: workspace_id.to_string(),
            })
        }
        ScopeKind::Team => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            let team = required_arg("team", team)?;
            Ok(CapabilityScope::Team {
                workspace_id: workspace_id.to_string(),
                team: team.to_string(),
            })
        }
    }
}

fn required_arg<'a>(name: &str, value: Option<&'a str>) -> Result<&'a str, String> {
    let value = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("--{} is required", name))?;
    Ok(value)
}

fn scope_matches_secret(
    scope: &SecretScope,
    requested: &ScopeKind,
    workspace_id: Option<&str>,
    team: Option<&str>,
) -> bool {
    match requested {
        ScopeKind::Global => matches!(scope, SecretScope::Global),
        ScopeKind::Workspace => matches!(
            scope,
            SecretScope::Workspace {
                workspace_id: ws
            } if Some(ws.as_str()) == workspace_id.map(str::trim)
        ),
        ScopeKind::Team => matches!(
            scope,
            SecretScope::Team {
                workspace_id: ws,
                team: t
            } if Some(ws.as_str()) == workspace_id.map(str::trim)
                && Some(t.as_str()) == team.map(str::trim)
        ),
    }
}

fn print_resolved_value(secret_ref: &str, value: Vec<u8>, raw: bool) -> Result<(), String> {
    if raw {
        let text = String::from_utf8(value)
            .map_err(|_| "secret is not valid UTF-8; use non-raw mode".to_string())?;
        println!("{}", text);
        return Ok(());
    }

    print_json(&serde_json::json!({
        "secretRef": secret_ref,
        "valueB64": base64::engine::general_purpose::STANDARD.encode(value)
    }))
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    println!("{}", raw);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_oauth_setup_plan;

    #[test]
    fn oauth_setup_plan_builds_external_consent_url() {
        let plan = build_oauth_setup_plan(
            "google",
            "https://accounts.example.com/oauth2/v2/auth",
            "client-123",
            "http://127.0.0.1:8080/callback",
            &[
                "gmail.readonly".to_string(),
                "calendar.readonly".to_string(),
            ],
            Some("state-xyz"),
        )
        .unwrap();

        let url = plan.get("consentUrl").and_then(|v| v.as_str()).unwrap();
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback"));
        assert!(url.contains("scope=gmail.readonly%20calendar.readonly"));
        assert!(url.contains("state=state-xyz"));
        assert!(plan
            .get("exchangeOutsideBroker")
            .and_then(|v| v.as_bool())
            .unwrap());
    }
}
