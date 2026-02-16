use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::io::Write;
use std::net::IpAddr;
#[cfg(debug_assertions)]
use std::net::SocketAddr;

use base64::Engine;
use reqwest::blocking::multipart::Form;
use reqwest::blocking::Client;
use reqwest::redirect::Policy as RedirectPolicy;
use serde::Serialize;
use serde_json::Value;

use crate::broker::{
    AllowPolicy, AuthStrategy, Broker, BrokerConfig, Capability, CapabilityAdvancedPolicy,
    CredentialInput, Header, MultipartFileSerde, PlannedRequest, ProviderTemplate, ProxyEnvelope,
    ProxyEnvelopeRequest, ProxyTokenMintRequest, Registry, RequestAuth, RequestBodyMode,
    SecretMaterial, UpstreamResponse,
};
use crate::broker_store::{BrokerStore, StoredCapabilityPolicy, StoredCredential};
use crate::capabilities::{CapabilityScope, CapabilityStore};
use crate::cli::{
    AuthKind, CapabilityCommand, CapabilityPolicyCommand, Cli, Command, CredentialCommand,
    InvokeArgs, OauthCommand, ProviderKind, ScopeKind, SecretsCommand, SetupCommand,
};
use crate::daemon::{self, DaemonRequest};
use crate::markdown::{to_markdown, ToMarkdownOptions};
use crate::vault::{
    read_audit_events, read_audit_events_before, SecretRef, SecretScope, VaultProviderConfig,
    VaultRuntime,
};

pub fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Invoke { args } => run_invoke_thin_or_local(args, InvokeOutputMode::Raw),
        Command::Json { args } => run_invoke_thin_or_local(args, InvokeOutputMode::Json),
        Command::Markdown {
            args,
            namespace,
            exclude_field,
            wrap_field,
        } => run_invoke_thin_or_local(
            args,
            InvokeOutputMode::Markdown {
                namespace,
                exclude_field,
                wrap_field,
            },
        ),
        Command::Setup { command } => run_setup(command),
        Command::Restart => run_restart_daemon(),
        // Everything else is "operator mode" and requires local vault access.
        other => {
            let vault = VaultRuntime::discover();
            vault.load().map_err(|e| e.to_string())?;
            crate::migrations::run_on_cli_startup(&vault)?;

            match other {
                Command::Status { verbose } => run_status(&vault, verbose),
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
                    crate::migrations::run_on_cli_startup(&vault)?;
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
                Command::Oauth { command } => run_oauth(command),
                Command::Credential { command } => run_credential(&vault, command),
                Command::Capability { command } => run_capability(&vault, command),
                // These are handled earlier.
                Command::Invoke { .. } | Command::Json { .. } | Command::Markdown { .. } => {
                    unreachable!("invoke handled earlier")
                }
                Command::Setup { .. } => unreachable!("setup handled earlier"),
                Command::Restart => unreachable!("restart handled earlier"),
            }
        }
    }
}

fn run_setup(command: SetupCommand) -> Result<(), String> {
    match command {
        SetupCommand::AgentAccess {
            agent_user,
            daemon_user,
            dry_run,
        } => run_setup_agent_access(&agent_user, daemon_user.as_deref(), dry_run),
        SetupCommand::Launchd { dry_run } => run_setup_launchd(dry_run),
        SetupCommand::Systemd {
            daemon_user,
            dry_run,
        } => run_setup_systemd(&daemon_user, dry_run),
    }
}

fn run_restart_daemon() -> Result<(), String> {
    #[cfg(not(unix))]
    {
        return Err("restart requires a unix-like OS".to_string());
    }

    #[cfg(unix)]
    {
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        let socket_path =
            daemon::socket_path_from_env().unwrap_or_else(daemon::default_socket_path);
        let socket = socket_path.display().to_string();

        // Best-effort stop of a daemon already bound to this exact socket.
        let pattern = format!("aivaultd --socket {}", socket);
        if let Ok(status) = Command::new("pkill").arg("-f").arg(&pattern).status() {
            if !status.success() && status.code() != Some(1) {
                return Err(format!(
                    "failed stopping existing aivaultd for '{}': exit {}",
                    socket, status
                ));
            }
        }

        // Remove stale socket entry before restart.
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        let daemon_exe = resolve_aivaultd_exe_path()?;
        let daemon_path = daemon_exe.display().to_string();
        Command::new(&daemon_exe)
            .arg("--socket")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to start aivaultd: {}", e))?;

        // Confirm the daemon is accepting requests before returning.
        let probe = DaemonRequest::ExecuteEnvelope {
            envelope: ProxyEnvelope {
                capability: "__aivault/health".to_string(),
                credential: None,
                request: ProxyEnvelopeRequest {
                    method: "GET".to_string(),
                    path: "/".to_string(),
                    headers: Vec::new(),
                    body: None,
                    multipart: None,
                    multipart_files: Vec::new(),
                    body_file_path: None,
                    url: None,
                },
            },
            client_ip: "127.0.0.1".to_string(),
            workspace_id: None,
            group_id: None,
        };

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match daemon::client_execute_envelope_typed(&socket_path, probe.clone()) {
                Ok(_) | Err(daemon::DaemonClientError::Remote(_)) => break,
                Err(daemon::DaemonClientError::Connect(_)) => {}
                Err(daemon::DaemonClientError::Protocol(err)) => {
                    return Err(format!("daemon protocol error after restart: {}", err));
                }
            }

            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for aivaultd on '{}': daemon did not accept connections",
                    socket
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }

        print_json(&serde_json::json!({
            "restarted": true,
            "socket": socket,
            "daemonPath": daemon_path
        }))
    }
}

fn read_trimmed_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(unix)]
fn require_root() -> Result<(), String> {
    let out = std::process::Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| format!("failed to run id: {}", e))?;
    if !out.status.success() {
        return Err("id -u failed".to_string());
    }
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if uid != "0" {
        return Err("this command requires sudo/root".to_string());
    }
    Ok(())
}

fn resolve_aivaultd_exe_path() -> Result<std::path::PathBuf, String> {
    // Prefer aivaultd alongside the current `aivault` executable.
    if let Ok(mut exe) = std::env::current_exe() {
        #[cfg(target_os = "windows")]
        {
            exe.set_file_name("aivaultd.exe");
        }
        #[cfg(not(target_os = "windows"))]
        {
            exe.set_file_name("aivaultd");
        }
        if exe.exists() {
            return Ok(exe);
        }
    }

    // Fall back to PATH lookup.
    let out = std::process::Command::new("which")
        .arg("aivaultd")
        .output()
        .map_err(|e| format!("failed to run which: {}", e))?;
    if !out.status.success() {
        return Err("could not locate aivaultd (not found in PATH)".to_string());
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if p.is_empty() {
        return Err("could not locate aivaultd (which returned empty output)".to_string());
    }
    Ok(std::path::PathBuf::from(p))
}

fn run_cmd(dry_run: bool, program: &str, args: &[String]) -> Result<(), String> {
    if dry_run {
        println!("$ {} {}", program, args.join(" "));
        return Ok(());
    }
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("failed to run {}: {}", program, e))?;
    if !status.success() {
        return Err(format!("command failed: {} (exit {})", program, status));
    }
    Ok(())
}

fn run_setup_agent_access(
    agent_user: &str,
    daemon_user: Option<&str>,
    dry_run: bool,
) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (agent_user, daemon_user, dry_run);
        return Err("agent-access setup requires a unix-like OS".to_string());
    }

    #[cfg(unix)]
    {
        require_root()?;

        let agent_user = agent_user.trim();
        if agent_user.is_empty() {
            return Err("--agent-user is required".to_string());
        }

        let daemon_user = daemon_user
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .or_else(|| read_trimmed_env("SUDO_USER"))
            .ok_or_else(|| "missing --daemon-user (and $SUDO_USER is not set)".to_string())?;

        let group = "aivault";
        let shared_socket = daemon::shared_socket_path();
        let shared_dir = shared_socket
            .parent()
            .ok_or_else(|| "shared socket path has no parent directory".to_string())?
            .to_path_buf();

        #[cfg(target_os = "macos")]
        {
            // Ensure group exists.
            let read_status = std::process::Command::new("dseditgroup")
                .args(["-o", "read", group])
                .status()
                .map_err(|e| format!("failed to run dseditgroup: {}", e))?;
            if !read_status.success() {
                let args = vec!["-o".to_string(), "create".to_string(), group.to_string()];
                run_cmd(dry_run, "dseditgroup", &args)?;
            }

            // Add daemon and agent users to group (idempotent).
            for user in [&daemon_user, agent_user].iter() {
                let args = vec![
                    "-o".to_string(),
                    "edit".to_string(),
                    "-a".to_string(),
                    user.to_string(),
                    "-t".to_string(),
                    "user".to_string(),
                    group.to_string(),
                ];
                run_cmd(dry_run, "dseditgroup", &args)?;
            }

            // Create socket directory with setgid so the socket inherits group ownership.
            let args = vec![
                "-d".to_string(),
                "-m".to_string(),
                "2750".to_string(),
                "-o".to_string(),
                daemon_user.clone(),
                "-g".to_string(),
                group.to_string(),
                shared_dir.to_string_lossy().to_string(),
            ];
            run_cmd(dry_run, "install", &args)?;
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            // Ensure group exists (idempotent).
            let group_exists = std::process::Command::new("getent")
                .args(["group", group])
                .status()
                .map_err(|e| format!("failed to run getent: {}", e))?
                .success();
            if !group_exists {
                let args = vec![group.to_string()];
                run_cmd(dry_run, "groupadd", &args)?;
            }

            // Add daemon and agent users to group.
            for user in [&daemon_user, agent_user].iter() {
                let args = vec!["-aG".to_string(), group.to_string(), user.to_string()];
                run_cmd(dry_run, "usermod", &args)?;
            }

            let args = vec![
                "-d".to_string(),
                "-m".to_string(),
                "2750".to_string(),
                "-o".to_string(),
                daemon_user.clone(),
                "-g".to_string(),
                group.to_string(),
                shared_dir.to_string_lossy().to_string(),
            ];
            run_cmd(dry_run, "install", &args)?;
        }

        println!(
            "Configured shared socket directory: {}",
            shared_dir.display()
        );
        println!(
            "Added users to group '{}': {}, {}",
            group, daemon_user, agent_user
        );
        println!();
        println!("Next steps:");
        println!("  1. Start the shared daemon:  aivaultd --shared");
        println!(
            "  2. On the agent account, run: aivault invoke <capability> ... (no env vars needed)"
        );

        Ok(())
    }
}

fn run_setup_launchd(dry_run: bool) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = dry_run;
        Err("launchd setup is only available on macOS".to_string())
    }

    #[cfg(target_os = "macos")]
    {
        let home =
            dirs::home_dir().ok_or_else(|| "could not resolve home directory".to_string())?;
        let agents_dir = home.join("Library").join("LaunchAgents");
        let logs_dir = home.join(".aivault").join("logs");
        let label = "com.aivault.aivaultd.shared";
        let plist_path = agents_dir.join(format!("{}.plist", label));

        let uid_out = std::process::Command::new("id")
            .arg("-u")
            .output()
            .map_err(|e| format!("failed to run id -u: {}", e))?;
        if !uid_out.status.success() {
            return Err("id -u failed".to_string());
        }
        let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
        if uid.is_empty() {
            return Err("id -u returned empty output".to_string());
        }

        let aivaultd = resolve_aivaultd_exe_path()?;

        if dry_run {
            println!("Would write: {}", plist_path.display());
        } else {
            std::fs::create_dir_all(&agents_dir).map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&logs_dir).map_err(|e| e.to_string())?;
        }

        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{exe}</string>
      <string>--shared</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
  </dict>
</plist>
"#,
            label = label,
            exe = aivaultd.to_string_lossy(),
            stdout = logs_dir.join("aivaultd.log").to_string_lossy(),
            stderr = logs_dir.join("aivaultd.err.log").to_string_lossy()
        );

        if dry_run {
            println!("{}", plist);
        } else {
            std::fs::write(&plist_path, plist.as_bytes()).map_err(|e| e.to_string())?;
        }

        let domain = format!("gui/{}", uid);
        let service = format!("{}/{}", domain, label);

        // Prefer modern launchctl flow; fall back to legacy load/unload for older systems.
        let bootout = vec![
            "bootout".into(),
            domain.clone(),
            plist_path.to_string_lossy().to_string(),
        ];
        let bootstrap = vec![
            "bootstrap".into(),
            domain.clone(),
            plist_path.to_string_lossy().to_string(),
        ];
        let enable = vec!["enable".into(), service.clone()];
        let kickstart = vec!["kickstart".into(), "-k".into(), service.clone()];

        // bootout may fail if not loaded; ignore in non-dry mode by not erroring on non-zero.
        if dry_run {
            run_cmd(dry_run, "launchctl", &bootout)?;
        } else {
            let _ = std::process::Command::new("launchctl")
                .args(&bootout)
                .status();
        }
        if let Err(e) = run_cmd(dry_run, "launchctl", &bootstrap) {
            // Legacy fallback.
            let load = vec![
                "load".into(),
                "-w".into(),
                plist_path.to_string_lossy().to_string(),
            ];
            run_cmd(dry_run, "launchctl", &load).map_err(|_| e)?;
        }
        let _ = run_cmd(dry_run, "launchctl", &enable);
        let _ = run_cmd(dry_run, "launchctl", &kickstart);

        println!("Installed launchd LaunchAgent: {}", plist_path.display());
        println!(
            "Daemon should be running on shared socket: {}",
            daemon::shared_socket_path().display()
        );
        Ok(())
    }
}

fn run_setup_systemd(daemon_user: &str, dry_run: bool) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (daemon_user, dry_run);
        return Err("systemd setup requires a unix-like OS".to_string());
    }

    #[cfg(unix)]
    {
        // systemd is a linux concept; return a clear error on macOS.
        #[cfg(target_os = "macos")]
        {
            let _ = (daemon_user, dry_run);
            Err("systemd setup is only available on Linux".to_string())
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            require_root()?;
            let daemon_user = daemon_user.trim();
            if daemon_user.is_empty() {
                return Err("--daemon-user is required".to_string());
            }

            let unit_name = "aivaultd-shared.service";
            let unit_path = std::path::PathBuf::from("/etc/systemd/system").join(unit_name);
            let aivaultd = resolve_aivaultd_exe_path()?;

            let unit = format!(
                r#"[Unit]
Description=aivault shared daemon (aivaultd --shared)
After=network.target

[Service]
Type=simple
User={daemon_user}
Group=aivault
ExecStart={exe} --shared
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
"#,
                daemon_user = daemon_user,
                exe = aivaultd.to_string_lossy()
            );

            if dry_run {
                println!("Would write: {}", unit_path.display());
                println!("{}", unit);
            } else {
                std::fs::write(&unit_path, unit.as_bytes()).map_err(|e| e.to_string())?;
            }

            run_cmd(dry_run, "systemctl", &["daemon-reload".into()])?;
            run_cmd(
                dry_run,
                "systemctl",
                &["enable".into(), "--now".into(), unit_name.into()],
            )?;

            println!("Installed systemd unit: {}", unit_path.display());
            println!(
                "Daemon should be running on shared socket: {}",
                daemon::shared_socket_path().display()
            );
            Ok(())
        }
    }
}

enum InvokeOutputMode {
    Raw,
    Json,
    Markdown {
        namespace: Option<String>,
        exclude_field: Vec<String>,
        wrap_field: Vec<String>,
    },
}

fn run_invoke_thin_or_local(args: InvokeArgs, mode: InvokeOutputMode) -> Result<(), String> {
    // In-process execution explicitly requested.
    if env_flag_true("AIVAULTD_DISABLE") {
        let vault = VaultRuntime::discover();
        vault.load().map_err(|e| e.to_string())?;
        crate::migrations::run_on_cli_startup(&vault)?;

        return match mode {
            InvokeOutputMode::Raw => run_invoke(&vault, args),
            InvokeOutputMode::Json => run_invoke_json(&vault, args),
            InvokeOutputMode::Markdown {
                namespace,
                exclude_field,
                wrap_field,
            } => run_invoke_markdown(&vault, args, namespace, exclude_field, wrap_field),
        };
    }

    // Try the daemon path without touching local vault state. This enables a "thin client"
    // workflow where untrusted agents can invoke capabilities via a shared unix socket without
    // having read access to the vault directory or key provider.
    //
    // If it fails, keep the error to report if local fallback also fails.
    let thin_err = match invoke_via_daemon_thin(args.clone()) {
        Ok(envelope_response) => {
            return match mode {
                InvokeOutputMode::Raw => print_invoke_body(&envelope_response),
                InvokeOutputMode::Json => invoke_json_from_envelope_response(&envelope_response),
                InvokeOutputMode::Markdown {
                    namespace,
                    exclude_field,
                    wrap_field,
                } => invoke_markdown_from_envelope_response(
                    &envelope_response,
                    namespace,
                    exclude_field,
                    wrap_field,
                ),
            };
        }
        Err(err) => err,
    };

    // Fall back to local execution (which will use the daemon boundary if available).
    let vault = VaultRuntime::discover();
    vault.load().map_err(|e| e.to_string())?;
    crate::migrations::run_on_cli_startup(&vault)?;

    let local_res = match mode {
        InvokeOutputMode::Raw => run_invoke(&vault, args),
        InvokeOutputMode::Json => run_invoke_json(&vault, args),
        InvokeOutputMode::Markdown {
            namespace,
            exclude_field,
            wrap_field,
        } => run_invoke_markdown(&vault, args, namespace, exclude_field, wrap_field),
    };
    if let Err(local_err) = local_res {
        // The thin-client error is often the most actionable when users are trying to connect to a
        // shared daemon socket. Surface it as context.
        return Err(format!(
            "{local_err}\n(thin client daemon attempt failed first: {thin_err})"
        ));
    }
    Ok(())
}

fn invoke_json_from_envelope_response(envelope_response: &Value) -> Result<(), String> {
    let planned = envelope_response
        .get("planned")
        .cloned()
        .ok_or_else(|| "missing planned in invoke output".to_string())?;
    let status = envelope_response
        .get("response")
        .and_then(|v| v.get("status"))
        .cloned()
        .ok_or_else(|| "missing response.status in invoke output".to_string())?;

    let bytes = extract_invoke_body_bytes(envelope_response)?;
    let json: Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "upstream response body is not valid JSON ({}); use `aivault invoke` for raw output",
            e
        )
    })?;

    let payload = serde_json::json!({
        "planned": planned,
        "response": {
            "status": status,
            "json": json
        }
    });
    print_json(&payload)
}

fn invoke_markdown_from_envelope_response(
    envelope_response: &Value,
    namespace: Option<String>,
    exclude_field: Vec<String>,
    wrap_field: Vec<String>,
) -> Result<(), String> {
    let bytes = extract_invoke_body_bytes(envelope_response)?;
    let value = if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
        json
    } else {
        let text = String::from_utf8(bytes)
            .map_err(|_| "upstream response body is not utf8 or json".to_string())?;
        Value::String(text)
    };

    let md = to_markdown(
        &value,
        &ToMarkdownOptions {
            namespace,
            exclude_fields: exclude_field,
            wrap_fields: wrap_field,
        },
    );
    print!("{}", md);
    Ok(())
}

fn run_status(vault: &VaultRuntime, verbose: bool) -> Result<(), String> {
    let status = vault.status();
    if verbose {
        let payload = serde_json::json!({
            "status": status,
            "paths": {
                "rootDir": vault.paths().root_dir().display().to_string(),
                "configPath": vault.paths().config_path().display().to_string(),
                "secretsDir": vault.paths().secrets_dir().display().to_string(),
                "auditDir": vault.paths().audit_dir().display().to_string(),
                "capabilitiesPath": vault.paths().root_dir().join("capabilities.json").display().to_string()
            }
        });
        return print_json(&payload);
    }
    crate::display::print_status(&status, &vault.paths().root_dir().display().to_string());
    Ok(())
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
            group_id,
            verbose,
        } => {
            let mut list = vault.list_secrets().map_err(|e| e.to_string())?;
            if let Some(scope_kind) = scope {
                list.retain(|meta| {
                    scope_matches_secret(
                        &meta.scope,
                        &scope_kind,
                        workspace_id.as_deref(),
                        group_id.as_deref(),
                    )
                });
            }
            if verbose {
                return print_json(&list);
            }
            crate::display::print_secrets_list(&list);
            Ok(())
        }
        SecretsCommand::Create {
            name,
            value,
            scope,
            workspace_id,
            group_id,
            alias,
        } => {
            let scope = parse_secret_scope(scope, workspace_id.as_deref(), group_id.as_deref())?;
            let mut meta = vault
                .create_secret(&name, value.as_bytes(), scope, alias)
                .map_err(|e| e.to_string())?;
            if let Ok(registry) = crate::registry::builtin_registry() {
                if let Some(template) =
                    registry_provider_template_claiming_secret_name(&registry, &meta.name)
                {
                    meta = vault
                        .pin_secret_to_provider(&meta.secret_id, &template.provider)
                        .map_err(|e| e.to_string())?;
                    eprintln!(
                        "Secret created: {} (pinned to provider: {})",
                        meta.name, template.provider
                    );
                    maybe_autoprovision_registry_credential(vault, &template, &meta.scope)?;
                }
            }
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
        SecretsCommand::AttachGroup {
            id,
            workspace_id,
            group_id,
        } => {
            let meta = vault
                .attach_secret_to_group(&id, &workspace_id, &group_id)
                .map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::DetachGroup {
            id,
            workspace_id,
            group_id,
        } => {
            let meta = vault
                .detach_secret_from_group(&id, &workspace_id, &group_id)
                .map_err(|e| e.to_string())?;
            print_json(&meta)
        }
        SecretsCommand::Import {
            entry,
            scope,
            workspace_id,
            group_id,
        } => {
            let scope = parse_secret_scope(scope, workspace_id.as_deref(), group_id.as_deref())?;
            let registry = crate::registry::builtin_registry().ok();
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
                        if let Some(registry) = registry.as_ref() {
                            if let Ok(meta) = vault.get_secret_meta(&secret_id) {
                                if let Some(template) =
                                    registry_provider_template_claiming_secret_name(
                                        registry, &meta.name,
                                    )
                                {
                                    let _ = vault.pin_secret_to_provider(
                                        &meta.secret_id,
                                        &template.provider,
                                    );
                                    let _ = maybe_autoprovision_registry_credential(
                                        vault,
                                        &template,
                                        &meta.scope,
                                    );
                                }
                            }
                        }
                    } else {
                        skipped.push(key);
                    }
                    continue;
                }

                match vault.create_secret(&key, value.as_bytes(), scope.clone(), Vec::new()) {
                    Ok(mut meta) => {
                        created.push(key.clone());
                        if let Some(registry) = registry.as_ref() {
                            if let Some(template) = registry_provider_template_claiming_secret_name(
                                registry, &meta.name,
                            ) {
                                if let Ok(pinned) = vault
                                    .pin_secret_to_provider(&meta.secret_id, &template.provider)
                                {
                                    meta = pinned;
                                }
                                let _ = maybe_autoprovision_registry_credential(
                                    vault,
                                    &template,
                                    &meta.scope,
                                );
                            }
                        }
                    }
                    Err(_) => skipped.push(key),
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

fn registry_provider_template_claiming_secret_name(
    registry: &Registry,
    secret_name: &str,
) -> Option<ProviderTemplate> {
    let wanted = secret_name.trim();
    if wanted.is_empty() {
        return None;
    }
    registry
        .providers()
        .into_iter()
        .find(|template| template.vault_secrets.contains_key(wanted))
}

fn credential_id_for_provider_scope(provider: &str, scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => provider.to_string(),
        SecretScope::Workspace { workspace_id } => format!("{}:ws:{}", provider, workspace_id),
        SecretScope::Group {
            workspace_id,
            group_id,
        } => format!("{}:group:{}:{}", provider, workspace_id, group_id),
    }
}

fn composite_secret_name_for_provider_scope(provider: &str, scope: &SecretScope) -> String {
    match scope {
        SecretScope::Global => format!("__aivault_registry:{}:global", provider),
        SecretScope::Workspace { workspace_id } => {
            format!("__aivault_registry:{}:workspace:{}", provider, workspace_id)
        }
        SecretScope::Group {
            workspace_id,
            group_id,
        } => format!(
            "__aivault_registry:{}:group:{}:{}",
            provider, workspace_id, group_id
        ),
    }
}

fn credential_context_for_secret_scope(scope: &SecretScope) -> (Option<String>, Option<String>) {
    match scope {
        SecretScope::Global => (None, None),
        SecretScope::Workspace { workspace_id } => (Some(workspace_id.clone()), None),
        SecretScope::Group {
            workspace_id,
            group_id,
        } => (Some(workspace_id.clone()), Some(group_id.clone())),
    }
}

fn hosts_within_registry_policy(template: &ProviderTemplate, hosts: &[String]) -> bool {
    !hosts.is_empty()
        && hosts.iter().all(|host| {
            template
                .hosts
                .iter()
                .any(|pattern| crate::broker::host_matches(pattern, host))
        })
}

fn registry_secret_ref_for_template_scope(
    vault: &VaultRuntime,
    template: &ProviderTemplate,
    scope: &SecretScope,
    by_name: &HashMap<String, crate::vault::SecretMeta>,
) -> Result<String, String> {
    let needs_composite_secret = matches!(
        &template.auth,
        AuthStrategy::MultiHeader(_) | AuthStrategy::MultiQuery(_) | AuthStrategy::Basic
    ) || template.vault_secrets.len() > 1;

    // For multi-secret providers (and for auth strategies that require structured secret
    // material), create/rotate a system-managed composite secret.
    let secret_ref = if !needs_composite_secret && template.vault_secrets.len() == 1 {
        let (name, _placeholder) = template.vault_secrets.iter().next().expect("len() == 1");
        let meta = by_name
            .get(name)
            .ok_or_else(|| "missing required secret".to_string())?;
        crate::vault::SecretRef {
            secret_id: meta.secret_id.clone(),
        }
        .to_string()
    } else {
        let mut fields = serde_json::Map::new();
        for (secret_name, placeholder) in &template.vault_secrets {
            let meta = by_name
                .get(secret_name)
                .ok_or_else(|| "missing required secret".to_string())?;
            let sr = crate::vault::SecretRef {
                secret_id: meta.secret_id.clone(),
            }
            .to_string();
            let raw = vault
                .resolve_secret_ref(
                    &sr,
                    Some("secret.autoprovision.compose"),
                    Some("aivault-cli"),
                )
                .map_err(|e| e.to_string())?;
            let value = String::from_utf8(raw).map_err(|_| {
                format!("secret '{}' must be utf-8 for composite auth", secret_name)
            })?;
            fields.insert(placeholder.clone(), serde_json::Value::String(value));
        }
        if matches!(&template.auth, AuthStrategy::Basic) && !fields.contains_key("username") {
            // Convenience default for common basic-auth APIs (e.g. Mailgun uses username "api").
            fields.insert(
                "username".to_string(),
                serde_json::Value::String("api".to_string()),
            );
        }
        let composite_value =
            serde_json::to_vec(&serde_json::Value::Object(fields)).map_err(|e| e.to_string())?;

        let composite_name = composite_secret_name_for_provider_scope(&template.provider, scope);
        let existing = by_name.get(&composite_name).map(|m| m.secret_id.clone());
        let composite_meta = if let Some(existing_id) = existing {
            let _ = vault
                .set_secret_system_managed(&existing_id, true)
                .map_err(|e| e.to_string())?;
            vault
                .rotate_secret_value(&existing_id, &composite_value)
                .map_err(|e| e.to_string())?
        } else {
            vault
                .create_system_secret(&composite_name, &composite_value, scope.clone(), Vec::new())
                .map_err(|e| e.to_string())?
        };
        let composite_meta = vault
            .pin_secret_to_provider(&composite_meta.secret_id, &template.provider)
            .map_err(|e| e.to_string())?;
        crate::vault::SecretRef {
            secret_id: composite_meta.secret_id,
        }
        .to_string()
    };

    Ok(secret_ref)
}

fn derive_registry_credentials_from_vault(
    vault: &VaultRuntime,
    store: Option<&BrokerStore>,
) -> Result<Vec<StoredCredential>, String> {
    let registry = crate::registry::builtin_registry().map_err(|e| e.to_string())?;
    let mut providers = registry.providers();
    providers.sort_by(|a, b| a.provider.cmp(&b.provider));

    let mut secrets_by_scope: BTreeMap<
        String,
        (SecretScope, HashMap<String, crate::vault::SecretMeta>),
    > = BTreeMap::new();
    for meta in vault.list_secrets().map_err(|e| e.to_string())? {
        if meta.revoked_at_ms.is_some() {
            continue;
        }
        let key = meta.scope.to_display_string();
        let entry = secrets_by_scope
            .entry(key)
            .or_insert_with(|| (meta.scope.clone(), HashMap::new()));
        entry.1.insert(meta.name.clone(), meta);
    }

    let mut out = Vec::new();
    for template in providers {
        if template.vault_secrets.is_empty() {
            continue;
        }

        for (scope, by_name) in secrets_by_scope.values() {
            let complete = template
                .vault_secrets
                .keys()
                .all(|secret_name| by_name.contains_key(secret_name));
            if !complete {
                continue;
            }

            let secret_ref =
                registry_secret_ref_for_template_scope(vault, &template, scope, by_name)?;
            let cred_id = credential_id_for_provider_scope(&template.provider, scope);
            let (workspace_id, group_id) = credential_context_for_secret_scope(scope);

            let mut hosts = template.hosts.clone();
            if let Some(store) = store {
                if let Some(existing) = store
                    .credentials()
                    .iter()
                    .find(|c| c.id == cred_id && c.provider == template.provider)
                {
                    if hosts_within_registry_policy(&template, &existing.hosts) {
                        hosts = existing.hosts.clone();
                    }
                }
            }

            out.push(StoredCredential {
                id: cred_id,
                provider: template.provider.clone(),
                workspace_id,
                group_id,
                auth: template.auth.clone(),
                hosts,
                secret_ref,
            });
        }
    }

    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn maybe_autoprovision_registry_credential(
    vault: &VaultRuntime,
    template: &ProviderTemplate,
    scope: &SecretScope,
) -> Result<(), String> {
    if template.vault_secrets.is_empty() {
        return Ok(());
    }

    // Completeness check: all provider-claimed secrets must exist in the same scope.
    let secrets = vault.list_secrets().map_err(|e| e.to_string())?;
    let mut by_name: HashMap<String, crate::vault::SecretMeta> = HashMap::new();
    for meta in secrets {
        if &meta.scope == scope {
            by_name.insert(meta.name.clone(), meta);
        }
    }

    let mut missing: Vec<String> = Vec::new();
    for name in template.vault_secrets.keys() {
        if !by_name.contains_key(name) {
            missing.push(name.clone());
        }
    }

    if !missing.is_empty() {
        if missing.len() == 1 {
            eprintln!(
                "Waiting for {} to complete {} credential",
                missing[0], template.provider
            );
        } else {
            eprintln!(
                "Waiting for {} to complete {} credential",
                missing.join(", "),
                template.provider
            );
        }
        return Ok(());
    }

    let secret_ref = registry_secret_ref_for_template_scope(vault, template, scope, &by_name)?;

    let mut store = BrokerStore::open_under(vault.paths().root_dir())?;
    let cred_id = credential_id_for_provider_scope(&template.provider, scope);
    let (workspace_id, group_id) = credential_context_for_secret_scope(scope);

    let desired = StoredCredential {
        id: cred_id.clone(),
        provider: template.provider.clone(),
        workspace_id,
        group_id,
        auth: template.auth.clone(),
        hosts: template.hosts.clone(),
        secret_ref,
    };

    let existing_credential = store
        .credentials()
        .iter()
        .find(|c| c.id == cred_id)
        .cloned();
    let credential_created = existing_credential.is_none();
    let credential_updated = existing_credential
        .as_ref()
        .is_some_and(|existing| existing != &desired);
    if credential_created || credential_updated {
        store.upsert_credential(desired);
    }

    let existing_capabilities = store.capabilities().to_vec();
    let mut capabilities_synced = 0usize;
    for cap in &template.capabilities {
        let already_synced = existing_capabilities
            .iter()
            .any(|existing| existing.id == cap.id && existing == cap);
        if !already_synced {
            capabilities_synced += 1;
        }
        store.upsert_capability(cap.clone());
    }

    if credential_created || credential_updated || capabilities_synced > 0 {
        store.save()?;
    }
    if credential_created {
        eprintln!(
            "Credential auto-provisioned: {} ({} capabilities enabled)",
            cred_id,
            template.capabilities.len()
        );
    } else if credential_updated {
        eprintln!(
            "Credential auto-reconciled: {} (registry auth/hosts/secret binding refreshed)",
            cred_id
        );
    }

    Ok(())
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
    let registry = crate::registry::builtin_registry().map_err(|e| e.to_string())?;

    match command {
        CredentialCommand::Create {
            id,
            provider,
            secret_ref,
            workspace_id,
            group_id,
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
            path_prefix_template,
            auth_header,
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

            let provider = provider.trim().to_string();
            if provider.is_empty() {
                return Err("credential provider is required".to_string());
            }
            let provider_defaults = registry.provider(&provider).cloned();

            let workspace_id = workspace_id
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string());
            let group_id = group_id
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string());
            if group_id.is_some() && workspace_id.is_none() {
                return Err("--workspace-id is required when --group-id is provided".to_string());
            }

            let mut auth_headers = Vec::new();
            for raw in auth_header {
                auth_headers.push(parse_key_value_pair(&raw, "--auth-header")?);
            }

            let auth = match auth {
                Some(auth_kind) => build_auth_strategy(
                    auth_kind,
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
                        path_prefix_template,
                        auth_headers,
                    },
                ),
                None => provider_defaults
                    .as_ref()
                    .map(|template| template.auth.clone())
                    .ok_or_else(|| {
                        "--auth is required when provider is not in built-in registry".to_string()
                    })?,
            };
            let hosts = if host.is_empty() {
                provider_defaults
                    .as_ref()
                    .map(|template| template.hosts.clone())
                    .ok_or_else(|| {
                        "at least one --host is required when provider is not in built-in registry"
                            .to_string()
                    })?
            } else {
                host
            };
            let parsed = SecretRef::parse(&secret_ref)?;
            let meta = vault
                .get_secret_meta(&parsed.secret_id)
                .map_err(|e| format!("secret does not exist: {}", e))?;
            if let Some(pinned) = meta.pinned_provider.as_deref() {
                if pinned != provider.as_str() {
                    return Err(format!(
                        "secret is pinned to provider '{}' and cannot be used for provider '{}'",
                        pinned, provider
                    ));
                }
            }

            let credential = StoredCredential {
                id,
                provider,
                workspace_id,
                group_id,
                auth,
                hosts,
                secret_ref,
            };
            store.upsert_credential(credential.clone());
            if let Some(template) = provider_defaults {
                for capability in template.capabilities {
                    store.upsert_capability(capability);
                }
            }
            store.save()?;
            print_json(&credential)
        }
        CredentialCommand::List { verbose } => {
            let mut merged: BTreeMap<String, StoredCredential> = BTreeMap::new();
            for credential in store.credentials().iter().cloned() {
                merged.insert(credential.id.clone(), credential);
            }
            for credential in derive_registry_credentials_from_vault(vault, Some(&store))? {
                merged.insert(credential.id.clone(), credential);
            }
            let credentials: Vec<StoredCredential> = merged.into_values().collect();

            if verbose {
                let payload = serde_json::json!({
                    "credentials": credentials,
                    "path": vault.paths().root_dir().join("broker.json").display().to_string()
                });
                return print_json(&payload);
            }
            crate::display::print_credentials_list(&credentials);
            Ok(())
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
        CapabilityCommand::List { verbose } => {
            let registry = crate::registry::builtin_registry().map_err(|e| e.to_string())?;
            let registry_providers = registry.providers();
            let derived_credentials = derive_registry_credentials_from_vault(vault, Some(&store))?;
            let credentialed_providers: HashSet<String> = store
                .credentials()
                .iter()
                .map(|c| c.provider.clone())
                .chain(derived_credentials.into_iter().map(|c| c.provider))
                .collect();

            let mut local_map: BTreeMap<String, Capability> = BTreeMap::new();
            for capability in store.capabilities() {
                if let Some(canonical) = registry.capability(&capability.id) {
                    local_map.insert(canonical.id.clone(), canonical);
                } else {
                    local_map.insert(capability.id.clone(), capability.clone());
                }
            }
            for provider in &registry_providers {
                if credentialed_providers.contains(&provider.provider) {
                    for capability in &provider.capabilities {
                        local_map.insert(capability.id.clone(), capability.clone());
                    }
                }
            }
            let local_capabilities: Vec<Capability> = local_map.into_values().collect();
            let local_ids: HashSet<&str> =
                local_capabilities.iter().map(|c| c.id.as_str()).collect();

            let mut registry_capabilities: Vec<Capability> = Vec::new();
            for provider in &registry_providers {
                for cap in &provider.capabilities {
                    if !local_ids.contains(cap.id.as_str()) {
                        registry_capabilities.push(cap.clone());
                    }
                }
            }
            registry_capabilities.sort_by(|a, b| a.id.cmp(&b.id));

            if verbose {
                let payload = serde_json::json!({
                    "capabilities": local_capabilities,
                    "registryCapabilities": registry_capabilities,
                    "policies": store.policies(),
                    "path": vault.paths().root_dir().join("broker.json").display().to_string()
                });
                return print_json(&payload);
            }

            crate::display::print_capabilities_list(
                &local_capabilities,
                &registry_capabilities,
                &registry_providers,
            );
            Ok(())
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
        CapabilityCommand::Json { args } => invoke_json_with_store(vault, &store, args),
        CapabilityCommand::Markdown {
            args,
            namespace,
            exclude_field,
            wrap_field,
        } => invoke_markdown_with_store(vault, &store, args, namespace, exclude_field, wrap_field),
        CapabilityCommand::Bindings {
            capability,
            scope,
            workspace_id,
            group_id,
            consumer,
            verbose,
        } => {
            let binding_store = CapabilityStore::open_under(vault.paths().root_dir())?;
            let scope_filter = if let Some(scope) = scope {
                Some(parse_capability_scope(
                    scope,
                    workspace_id.as_deref(),
                    group_id.as_deref(),
                )?)
            } else {
                None
            };

            let mut list = binding_store.list();
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
            if verbose {
                return print_json(&list);
            }
            crate::display::print_bindings_list(&list);
            Ok(())
        }
        CapabilityCommand::Bind {
            capability,
            secret_ref,
            scope,
            workspace_id,
            group_id,
            consumer,
        } => {
            let mut binding_store = CapabilityStore::open_under(vault.paths().root_dir())?;
            let parsed = SecretRef::parse(&secret_ref)?;
            let meta = vault
                .get_secret_meta(&parsed.secret_id)
                .map_err(|e| format!("secret does not exist: {}", e))?;
            if let Some(pinned) = meta.pinned_provider.as_deref() {
                let registry = crate::registry::builtin_registry().map_err(|e| e.to_string())?;
                let cap = store
                    .find_capability(capability.trim())
                    .cloned()
                    .or_else(|| registry.capability(capability.trim()));
                let cap_provider = cap.as_ref().map(|c| c.provider.as_str());
                if cap_provider != Some(pinned) {
                    return Err(format!(
                        "secret is pinned to provider '{}' and cannot be bound to capability '{}' (provider {:?})",
                        pinned,
                        capability.trim(),
                        cap_provider
                    ));
                }
            }

            let scope =
                parse_capability_scope(scope, workspace_id.as_deref(), group_id.as_deref())?;
            let binding = binding_store.upsert(&capability, &secret_ref, scope, consumer)?;
            binding_store.save()?;
            print_json(&binding)
        }
        CapabilityCommand::Unbind {
            capability,
            scope,
            workspace_id,
            group_id,
            consumer,
        } => {
            let mut binding_store = CapabilityStore::open_under(vault.paths().root_dir())?;
            let scope =
                parse_capability_scope(scope, workspace_id.as_deref(), group_id.as_deref())?;
            let removed = binding_store.remove(&capability, &scope, consumer.as_deref());
            if removed {
                binding_store.save()?;
            }
            print_json(&serde_json::json!({
                "removed": removed,
                "path": binding_store.path().display().to_string()
            }))
        }
    }
}

fn run_invoke(vault: &VaultRuntime, args: InvokeArgs) -> Result<(), String> {
    let store = BrokerStore::open_under(vault.paths().root_dir())?;
    invoke_with_store(vault, &store, args)
}

fn run_invoke_json(vault: &VaultRuntime, args: InvokeArgs) -> Result<(), String> {
    let store = BrokerStore::open_under(vault.paths().root_dir())?;
    invoke_json_with_store(vault, &store, args)
}

fn run_invoke_markdown(
    vault: &VaultRuntime,
    args: InvokeArgs,
    namespace: Option<String>,
    exclude_field: Vec<String>,
    wrap_field: Vec<String>,
) -> Result<(), String> {
    let store = BrokerStore::open_under(vault.paths().root_dir())?;
    invoke_markdown_with_store(vault, &store, args, namespace, exclude_field, wrap_field)
}

fn invoke_with_store(
    vault: &VaultRuntime,
    store: &BrokerStore,
    args: InvokeArgs,
) -> Result<(), String> {
    let (workspace_id, group_id) =
        normalize_invoke_context(args.workspace_id.as_deref(), args.group_id.as_deref())?;
    let id = args.id.trim().to_string();
    let envelope = if let Some(capability) = lookup_capability_for_invoke(store, &id) {
        build_capability_call_envelope(&capability, args.clone())?
    } else {
        build_capability_call_envelope_without_local_capability(&id, args.clone())?
    };
    let client_ip: IpAddr = args
        .client_ip
        .parse()
        .map_err(|_| "invalid --client-ip".to_string())?;
    let response =
        maybe_run_capability_envelope(vault, store, envelope, client_ip, workspace_id, group_id)?;
    print_invoke_body(&response)
}

fn invoke_json_with_store(
    vault: &VaultRuntime,
    store: &BrokerStore,
    args: InvokeArgs,
) -> Result<(), String> {
    let (workspace_id, group_id) =
        normalize_invoke_context(args.workspace_id.as_deref(), args.group_id.as_deref())?;
    let id = args.id.trim().to_string();
    let envelope = if let Some(capability) = lookup_capability_for_invoke(store, &id) {
        build_capability_call_envelope(&capability, args.clone())?
    } else {
        build_capability_call_envelope_without_local_capability(&id, args.clone())?
    };
    let client_ip: IpAddr = args
        .client_ip
        .parse()
        .map_err(|_| "invalid --client-ip".to_string())?;
    let response =
        maybe_run_capability_envelope(vault, store, envelope, client_ip, workspace_id, group_id)?;

    let planned = response
        .get("planned")
        .cloned()
        .ok_or_else(|| "missing planned in invoke output".to_string())?;
    let status = response
        .get("response")
        .and_then(|v| v.get("status"))
        .cloned()
        .ok_or_else(|| "missing response.status in invoke output".to_string())?;

    let bytes = extract_invoke_body_bytes(&response)?;
    let json: Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "upstream response body is not valid JSON ({}); use `aivault invoke` for raw output",
            e
        )
    })?;

    let payload = serde_json::json!({
        "planned": planned,
        "response": {
            "status": status,
            "json": json
        }
    });
    print_json(&payload)
}

fn invoke_markdown_with_store(
    vault: &VaultRuntime,
    store: &BrokerStore,
    args: InvokeArgs,
    namespace: Option<String>,
    exclude_field: Vec<String>,
    wrap_field: Vec<String>,
) -> Result<(), String> {
    let (workspace_id, group_id) =
        normalize_invoke_context(args.workspace_id.as_deref(), args.group_id.as_deref())?;
    let id = args.id.trim().to_string();
    let envelope = if let Some(capability) = lookup_capability_for_invoke(store, &id) {
        build_capability_call_envelope(&capability, args.clone())?
    } else {
        build_capability_call_envelope_without_local_capability(&id, args.clone())?
    };
    let client_ip: IpAddr = args
        .client_ip
        .parse()
        .map_err(|_| "invalid --client-ip".to_string())?;
    let response =
        maybe_run_capability_envelope(vault, store, envelope, client_ip, workspace_id, group_id)?;

    let bytes = extract_invoke_body_bytes(&response)?;
    let value = if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
        json
    } else {
        let text = String::from_utf8(bytes)
            .map_err(|_| "upstream response body is not utf8 or json".to_string())?;
        Value::String(text)
    };

    let md = to_markdown(
        &value,
        &ToMarkdownOptions {
            namespace,
            exclude_fields: exclude_field,
            wrap_fields: wrap_field,
        },
    );
    print!("{}", md);
    Ok(())
}

fn invoke_via_daemon_thin(args: InvokeArgs) -> Result<Value, String> {
    let (workspace_id, group_id) =
        normalize_invoke_context(args.workspace_id.as_deref(), args.group_id.as_deref())?;

    // Build an envelope without reading any local vault or broker store state.
    // If the capability is registry-backed, we can still apply default method/path rules
    // (only when unambiguous). Otherwise, require --method/--path or --request payload.
    let capability_id = args.id.trim().to_string();
    if capability_id.is_empty() {
        return Err("capability id required".to_string());
    }

    let has_payload = args.request.is_some() || args.request_file.is_some();
    let has_method_or_path = args
        .method
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
        || args
            .path
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

    let envelope = if has_payload {
        build_capability_call_envelope_without_local_capability(&capability_id, args.clone())?
    } else {
        let registry_capability = crate::registry::builtin_registry()
            .ok()
            .and_then(|r| r.capability(&capability_id));
        if let Some(capability) = registry_capability {
            build_capability_call_envelope(&capability, args.clone())?
        } else if has_method_or_path {
            build_capability_call_envelope_without_local_capability(&capability_id, args.clone())?
        } else {
            return Err(format!(
                "capability '{}' is not available locally; pass --method/--path or use --request/--request-file",
                capability_id
            ));
        }
    };

    let client_ip: IpAddr = args
        .client_ip
        .parse()
        .map_err(|_| "invalid --client-ip".to_string())?;

    let request = DaemonRequest::ExecuteEnvelope {
        envelope,
        client_ip: client_ip.to_string(),
        workspace_id: workspace_id.map(|s| s.to_string()),
        group_id: group_id.map(|s| s.to_string()),
    };

    // Thin invoke: try connecting without autostart (this path is meant to work even when the
    // caller cannot read local vault state).
    let env_socket = daemon::socket_path_from_env();
    if let Some(p) = env_socket {
        return daemon::client_execute_envelope(&p, request);
    }

    let user_socket = daemon::default_socket_path();
    let shared_socket = daemon::shared_socket_path();

    let attempt = daemon::client_execute_envelope_typed(&user_socket, request.clone());
    match attempt {
        Ok(v) => return Ok(v),
        Err(crate::daemon::DaemonClientError::Connect(_)) => { /* fall through */ }
        Err(crate::daemon::DaemonClientError::Protocol(e)) => {
            return Err(format!(
                "invalid response from aivaultd at '{}': {}",
                user_socket.display(),
                e
            ));
        }
        Err(crate::daemon::DaemonClientError::Remote(e)) => return Err(e),
    }

    let attempt = daemon::client_execute_envelope_typed(&shared_socket, request);
    attempt.map_err(|e| match e {
        crate::daemon::DaemonClientError::Connect(err) => format!(
            "failed connecting to aivaultd (tried '{}' and '{}'): {}",
            user_socket.display(),
            shared_socket.display(),
            err
        ),
        crate::daemon::DaemonClientError::Protocol(err) => format!(
            "invalid response from aivaultd at '{}': {}",
            shared_socket.display(),
            err
        ),
        crate::daemon::DaemonClientError::Remote(err) => err,
    })
}

fn print_invoke_body(envelope_response: &Value) -> Result<(), String> {
    let bytes = extract_invoke_body_bytes(envelope_response)?;

    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes).map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())
}

fn extract_invoke_body_bytes(envelope_response: &Value) -> Result<Vec<u8>, String> {
    let body_b64 = envelope_response
        .get("response")
        .and_then(|r| r.get("bodyB64"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing response.bodyB64 in invoke output".to_string())?;

    base64::engine::general_purpose::STANDARD
        .decode(body_b64)
        .map_err(|e| format!("invalid base64 bodyB64: {}", e))
}

fn print_capability_call_args(store: &BrokerStore, id: &str) -> Result<(), String> {
    let id = id.trim();
    let capability = store
        .find_capability(id)
        .cloned()
        .or_else(|| {
            crate::registry::builtin_registry()
                .ok()
                .and_then(|r| r.capability(id))
        })
        .ok_or_else(|| format!("capability '{}' not found", id))?;

    // `describe` is primarily a "how do I call this?" UX. Defaults must only be set when the
    // capability shape is unambiguous, but we still include structured guidance so users can learn
    // how to invoke multi-method / multi-path capabilities without reading the source.
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

    let mut notes: Vec<String> = Vec::new();
    if default_method.is_none() {
        notes.push(format!(
            "Multiple methods allowed; pass --method (one of: {}).",
            capability.allow.methods.join(", ")
        ));
    } else if let Some(m) = &default_method {
        notes.push(format!("Default method is {} (only allowed method).", m));
    }
    if default_path.is_none() {
        notes.push(format!(
            "Multiple path prefixes allowed; pass --path (must start with one of: {}).",
            capability.allow.path_prefixes.join(", ")
        ));
    } else if let Some(p) = &default_path {
        notes.push(format!(
            "Default path prefix is {} (only allowed path prefix).",
            p
        ));
    }
    notes.push(
        "Use --request / --request-file to supply a full request object (method/path/headers/body) in one go."
            .to_string(),
    );
    notes.push(
        "If you have multiple credentials for the same provider, pin one with --credential <id>."
            .to_string(),
    );

    let method_hint = capability
        .allow
        .methods
        .iter()
        .find(|m| m.as_str() == "POST")
        .cloned()
        .or_else(|| capability.allow.methods.first().cloned())
        .unwrap_or_else(|| "GET".to_string());
    let path_hint = capability
        .allow
        .path_prefixes
        .first()
        .cloned()
        .unwrap_or_else(|| "/".to_string());

    let mut examples: Vec<Value> = Vec::new();
    let mut minimal = format!("aivault invoke {}", capability.id);
    if default_method.is_none() {
        minimal.push_str(&format!(" --method {}", method_hint));
    }
    if default_path.is_none() {
        minimal.push_str(&format!(" --path {}", path_hint));
    }
    examples.push(serde_json::json!({
        "title": "Minimal invocation (add required flags)",
        "command": minimal
    }));

    // For capabilities that are commonly JSON POSTs, show a "body" example without pretending to
    // know the upstream schema.
    if capability.allow.methods.iter().any(|m| m == "POST") {
        let mut json_post = format!("aivault invoke {}", capability.id);
        if default_method.is_none() {
            json_post.push_str(" --method POST");
        }
        if default_path.is_none() {
            json_post.push_str(&format!(" --path {}", path_hint));
        }
        json_post.push_str(" --header content-type=application/json --body '{\"todo\":\"fill\"}'");
        examples.push(serde_json::json!({
            "title": "JSON body example (when upstream expects JSON)",
            "command": json_post
        }));
    }

    // Template objects for `--request` / `--request-file`.
    let request_template = serde_json::json!({
        "method": default_method.clone().unwrap_or_else(|| method_hint.clone()),
        "path": default_path.clone().unwrap_or_else(|| path_hint.clone()),
        "headers": []
    });
    let envelope_template = serde_json::json!({
        "capability": capability.id,
        "request": request_template
    });
    let request_inline_payload = serde_json::json!({
        "method": default_method.clone().unwrap_or_else(|| method_hint.clone()),
        "path": default_path.clone().unwrap_or_else(|| path_hint.clone()),
        "headers": []
    });
    let request_inline = format!(
        "aivault invoke {} --request '{}'",
        capability.id, request_inline_payload
    );
    examples.push(serde_json::json!({
        "title": "Inline request payload example",
        "command": request_inline
    }));

    let how_to = serde_json::json!({
        "notes": notes,
        "examples": examples,
        "templates": {
            "request": request_template,
            "envelope": envelope_template
        }
    });

    // Include setup instructions with required vault secret names from registry.
    let setup = crate::registry::builtin_registry().ok().and_then(|reg| {
        let template = reg.provider(&capability.provider)?;
        if template.vault_secrets.is_empty() {
            return None;
        }
        let mut secret_names: Vec<&String> = template.vault_secrets.keys().collect();
        secret_names.sort();
        let commands: Vec<String> = secret_names
            .iter()
            .map(|name| {
                format!(
                    "aivault secrets create --name {} --value \"...\" --scope global",
                    name
                )
            })
            .collect();
        Some(serde_json::json!({
            "requiredSecrets": template.vault_secrets,
            "commands": commands,
            "note": "Credential and capabilities auto-provision when all required secrets are present."
        }))
    });

    let payload = serde_json::json!({
        "capability": capability.id,
        "provider": capability.provider,
        "setup": setup,
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
                "--workspace-id ID",
                "--group-id ID",
                "--client-ip IP"
            ],
            "payloadModes": [
                "--request '<json request or envelope>'",
                "--request-file <path>"
            ],
            "howTo": how_to
        }
    });
    print_json(&payload)
}

fn normalize_invoke_context<'a>(
    workspace_id: Option<&'a str>,
    group_id: Option<&'a str>,
) -> Result<(Option<&'a str>, Option<&'a str>), String> {
    let ws = workspace_id.map(str::trim).filter(|v| !v.is_empty());
    let group_id = group_id.map(str::trim).filter(|v| !v.is_empty());
    if group_id.is_some() && ws.is_none() {
        return Err("--workspace-id is required when --group-id is provided".to_string());
    }
    if ws.is_some() && group_id.is_none() {
        return Err("--group-id is required when --workspace-id is provided".to_string());
    }
    Ok((ws, group_id))
}

fn lookup_capability_for_invoke(store: &BrokerStore, id: &str) -> Option<Capability> {
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    store.find_capability(id).cloned().or_else(|| {
        crate::registry::builtin_registry()
            .ok()
            .and_then(|r| r.capability(id))
    })
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
        workspace_id: _,
        group_id: _,
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

fn build_capability_call_envelope_without_local_capability(
    capability_id: &str,
    args: InvokeArgs,
) -> Result<ProxyEnvelope, String> {
    let capability_id = capability_id.trim();
    if capability_id.is_empty() {
        return Err("capability id required".to_string());
    }

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
        workspace_id: _,
        group_id: _,
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
                capability: capability_id.to_string(),
                credential: None,
                request,
            }
        };

        if envelope.capability.trim().is_empty() {
            envelope.capability = capability_id.to_string();
        } else if envelope.capability != capability_id {
            return Err(format!(
                "request capability '{}' does not match command capability '{}'",
                envelope.capability, capability_id
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

    let method = method
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
        .ok_or_else(|| {
            "--method is required (capability policy not available locally)".to_string()
        })?;
    let path = path
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            "--path is required (capability policy not available locally)".to_string()
        })?;

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
        capability: capability_id.to_string(),
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

pub(crate) fn run_capability_envelope(
    vault: &VaultRuntime,
    store: &BrokerStore,
    envelope: ProxyEnvelope,
    client_ip: IpAddr,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<Value, String> {
    let mut broker = load_runtime_broker_for_context(
        vault,
        store,
        envelope.credential.as_deref(),
        workspace_id,
        group_id,
    )?;
    let token = broker
        .mint_proxy_token(
            &RequestAuth::Operator("operator-cli".to_string()),
            ProxyTokenMintRequest {
                capabilities: vec![envelope.capability.clone()],
                credential: envelope.credential.clone(),
                ttl_ms: 60_000,
                context: {
                    let mut ctx =
                        HashMap::from([("source".to_string(), "aivault-cli".to_string())]);
                    if let (Some(ws), Some(group_id)) = (
                        workspace_id.map(str::trim).filter(|v| !v.is_empty()),
                        group_id.map(str::trim).filter(|v| !v.is_empty()),
                    ) {
                        ctx.insert("workspaceId".to_string(), ws.to_string());
                        ctx.insert("groupId".to_string(), group_id.to_string());
                    }
                    ctx
                },
            },
        )
        .map_err(|e| e.to_string())?;

    let planned = match broker.execute_envelope(
        &RequestAuth::Proxy(token.token.clone()),
        envelope.clone(),
        client_ip,
    ) {
        Ok(planned) => planned,
        Err(err) if err.error == crate::broker::ErrorCode::OauthRefreshRequired => {
            // Refresh oauth2 secrets within the trusted vault boundary, then retry planning once.
            refresh_oauth2_for_envelope(
                vault,
                store,
                &mut broker,
                &envelope,
                &token,
                workspace_id,
                group_id,
            )?;
            broker
                .execute_envelope(&RequestAuth::Proxy(token.token), envelope, client_ip)
                .map_err(|e| e.to_string())?
        }
        Err(err) => return Err(err.to_string()),
    };
    execute_planned_http_request(&broker, &planned)
}

fn refresh_oauth2_for_envelope(
    vault: &VaultRuntime,
    store: &BrokerStore,
    broker: &mut Broker,
    envelope: &ProxyEnvelope,
    token: &crate::broker::ProxyToken,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<(), String> {
    let credential = broker
        .resolve_credential_for_capability(
            &envelope.capability,
            envelope.credential.as_deref(),
            token.credential.as_deref(),
        )
        .map_err(|e| e.to_string())?;

    let AuthStrategy::OAuth2 { .. } = credential.auth else {
        return Ok(());
    };

    let client = build_http_client_with_dev_overrides()?;
    let refreshed = refresh_oauth2_and_writeback(
        vault,
        store,
        &credential.id,
        workspace_id,
        group_id,
        &client,
    )?;
    broker
        .upsert_secret_material(&credential.id, refreshed)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn refresh_oauth2_and_writeback(
    vault: &VaultRuntime,
    store: &BrokerStore,
    credential_id: &str,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
    client: &Client,
) -> Result<SecretMaterial, String> {
    let stored = store
        .credentials()
        .iter()
        .find(|c| c.id == credential_id)
        .ok_or_else(|| format!("credential '{}' not found in broker store", credential_id))?;

    let AuthStrategy::OAuth2 {
        grant_type,
        token_endpoint,
        scopes,
    } = &stored.auth
    else {
        return Err("credential is not oauth2".to_string());
    };

    let secret_bytes = resolve_secret_ref_for_context(
        vault,
        &stored.secret_ref,
        workspace_id,
        group_id,
        Some("broker.auth.oauth2.refresh"),
        Some("aivault-cli"),
    )?;
    let material = secret_material_from_bytes(&stored.auth, secret_bytes.clone())?;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let skew_ms = 30_000i64;
    if let SecretMaterial::OAuth2 {
        client_id: _,
        client_secret: _,
        refresh_token: _,
        access_token: Some(_),
        access_token_expires_at_ms: Some(expires_at),
    } = &material
    {
        if *expires_at > now_ms + skew_ms {
            return Ok(material);
        }
    }

    let parsed = SecretRef::parse(&stored.secret_ref)?;
    let secret_id = parsed.secret_id;

    let SecretMaterial::OAuth2 {
        client_id,
        client_secret,
        refresh_token,
        access_token: _,
        access_token_expires_at_ms: _,
    } = material
    else {
        return Err(
            "oauth2 secret must be JSON with clientId/clientSecret/refreshToken".to_string(),
        );
    };

    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        return Err("missing oauth2 client credentials".to_string());
    }

    let token_url = reqwest::Url::parse(token_endpoint)
        .map_err(|_| "invalid oauth2 tokenEndpoint url".to_string())?;
    if token_url.scheme() != "https" {
        return Err("oauth2 tokenEndpoint must use https".to_string());
    }
    let token_host = token_url
        .host_str()
        .ok_or_else(|| "oauth2 tokenEndpoint host is required".to_string())?
        .to_string();
    let token_port = token_url.port();
    if token_port.is_some_and(|p| p != 443) && !dev_flag_true("AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS")
    {
        return Err("oauth2 tokenEndpoint non-default port not allowed".to_string());
    }
    let token_authority = if let Some(port) = token_port {
        format!("{}:{}", token_host, port)
    } else {
        token_host.clone()
    };
    if !stored
        .hosts
        .iter()
        .any(|pattern| crate::broker::host_matches(pattern, &token_authority))
    {
        return Err("oauth2 tokenEndpoint host is not allowed by credential hosts".to_string());
    }

    let mut params: Vec<(&str, String)> = Vec::new();
    params.push(("client_id", client_id.clone()));
    if grant_type.eq_ignore_ascii_case("client_credentials") {
        params.push(("grant_type", "client_credentials".to_string()));
    } else {
        if refresh_token.trim().is_empty() {
            return Err("missing oauth2 refresh token".to_string());
        }
        params.push(("grant_type", "refresh_token".to_string()));
        params.push(("refresh_token", refresh_token.clone()));
    }
    if !scopes.is_empty() {
        let scope = scopes
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !scope.is_empty() {
            params.push(("scope", scope));
        }
    }

    let response = client
        .post(token_url)
        .basic_auth(client_id.clone(), Some(client_secret.clone()))
        .form(&params)
        .send()
        .map_err(|e| format!("oauth2 token exchange failed: {}", format_reqwest_error(&e)))?;

    let status = response.status().as_u16();
    let body_bytes = response.bytes().map_err(|e| e.to_string())?.to_vec();
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    if !(200..300).contains(&status) {
        return Err(format!(
            "oauth2 token endpoint returned {}: {}",
            status, body_text
        ));
    }
    let json: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|_| "oauth2 token response must be JSON".to_string())?;
    let access_token = json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "oauth2 token response missing access_token".to_string())?
        .to_string();
    let expires_in = json
        .get("expires_in")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "oauth2 token response missing expires_in".to_string())?;
    let access_token_expires_at_ms = chrono::Utc::now().timestamp_millis() + (expires_in * 1000);
    let refresh_token = json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or(refresh_token);

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OAuth2SecretWrite {
        client_id: String,
        client_secret: String,
        #[serde(default)]
        refresh_token: String,
        access_token: Option<String>,
        access_token_expires_at_ms: Option<i64>,
    }

    let updated = OAuth2SecretWrite {
        client_id: client_id.clone(),
        client_secret: client_secret.clone(),
        refresh_token: refresh_token.clone(),
        access_token: Some(access_token.clone()),
        access_token_expires_at_ms: Some(access_token_expires_at_ms),
    };
    let updated_bytes = serde_json::to_vec(&updated).map_err(|e| e.to_string())?;
    vault
        .rotate_secret_value(&secret_id, &updated_bytes)
        .map_err(|e| e.to_string())?;

    Ok(SecretMaterial::OAuth2 {
        client_id,
        client_secret,
        refresh_token,
        access_token: Some(access_token),
        access_token_expires_at_ms: Some(access_token_expires_at_ms),
    })
}

fn maybe_run_capability_envelope(
    vault: &VaultRuntime,
    store: &BrokerStore,
    envelope: ProxyEnvelope,
    client_ip: IpAddr,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<Value, String> {
    if env_flag_true("AIVAULTD_DISABLE") {
        return run_capability_envelope(vault, store, envelope, client_ip, workspace_id, group_id);
    }

    // Default to daemon-backed execution on unix platforms. This keeps CLI UX as `aivault <cmd>`
    // while ensuring secret use happens in the daemon boundary when available.
    #[cfg(unix)]
    let env_socket = daemon::socket_path_from_env();
    #[cfg(unix)]
    let user_socket = daemon::default_socket_path();
    #[cfg(unix)]
    let shared_socket = daemon::shared_socket_path();

    #[cfg(unix)]
    {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let request = DaemonRequest::ExecuteEnvelope {
            envelope: envelope.clone(),
            client_ip: client_ip.to_string(),
            workspace_id: workspace_id.map(|s| s.to_string()),
            group_id: group_id.map(|s| s.to_string()),
        };

        let autostart_enabled = std::env::var("AIVAULTD_AUTOSTART")
            .ok()
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);

        let aivault_dir_set = std::env::var("AIVAULT_DIR")
            .ok()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let autostart_once = env_flag_true("AIVAULTD_AUTOSTART_ONCE") || aivault_dir_set;

        let autostart_and_retry = |socket_path: &std::path::Path| -> Result<Value, String> {
            if !autostart_enabled {
                return Err(format!(
                    "aivaultd not running at '{}' (autostart disabled)",
                    socket_path.display()
                ));
            }

            // Try to locate aivaultd alongside the current executable first.
            let mut daemon_exe = std::env::current_exe()
                .ok()
                .unwrap_or_else(|| std::path::PathBuf::from("aivault"));
            #[cfg(target_os = "windows")]
            {
                daemon_exe.set_file_name("aivaultd.exe");
            }
            #[cfg(not(target_os = "windows"))]
            {
                daemon_exe.set_file_name("aivaultd");
            }
            if !daemon_exe.exists() {
                daemon_exe = std::path::PathBuf::from("aivaultd");
            }

            let mut cmd = Command::new(daemon_exe);
            cmd.arg("--socket")
                .arg(socket_path.to_string_lossy().to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if autostart_once {
                cmd.arg("--once");
            }

            let mut child = cmd
                .spawn()
                .map_err(|e| format!("failed to start aivaultd: {}", e))?;

            // Wait for the daemon to become connectable, then retry the request.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match daemon::client_execute_envelope_typed(socket_path, request.clone()) {
                    Ok(value) => {
                        if autostart_once {
                            let _ = child.wait();
                        }
                        return Ok(value);
                    }
                    Err(crate::daemon::DaemonClientError::Connect(_)) => {
                        if Instant::now() > deadline {
                            if autostart_once {
                                let _ = child.wait();
                            }
                            return Err(format!(
                                "failed connecting to aivaultd at '{}' after autostart",
                                socket_path.display()
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(crate::daemon::DaemonClientError::Protocol(e)) => {
                        if autostart_once {
                            let _ = child.wait();
                        }
                        return Err(format!(
                            "invalid response from aivaultd at '{}': {}",
                            socket_path.display(),
                            e
                        ));
                    }
                    Err(crate::daemon::DaemonClientError::Remote(e)) => {
                        if autostart_once {
                            let _ = child.wait();
                        }
                        return Err(e);
                    }
                }
            }
        };

        // Socket auto-discovery order (PRD):
        // 1) AIVAULTD_SOCKET
        // 2) per-user default
        // 3) shared socket path
        //
        // Autostart is only attempted for the per-user socket after we've failed to connect to both
        // per-user and shared sockets. This ensures agents don't autostart their own daemon when a
        // shared operator daemon is available.
        if let Some(p) = env_socket {
            let attempt = daemon::client_execute_envelope_typed(&p, request.clone());
            return match attempt {
                Ok(v) => Ok(v),
                Err(crate::daemon::DaemonClientError::Connect(_)) => {
                    if p == shared_socket {
                        Err(format!(
                            "failed connecting to aivaultd at '{}' (shared socket; autostart suppressed)",
                            p.display()
                        ))
                    } else {
                        autostart_and_retry(&p)
                    }
                }
                Err(crate::daemon::DaemonClientError::Protocol(err)) => Err(format!(
                    "invalid response from aivaultd at '{}': {}",
                    p.display(),
                    err
                )),
                Err(crate::daemon::DaemonClientError::Remote(err)) => Err(err),
            };
        }

        // Try per-user socket first.
        let attempt = daemon::client_execute_envelope_typed(&user_socket, request.clone());
        match attempt {
            Ok(v) => Ok(v),
            Err(crate::daemon::DaemonClientError::Connect(_)) => {
                // Then try shared socket (no autostart here).
                let shared_attempt =
                    daemon::client_execute_envelope_typed(&shared_socket, request.clone());
                match shared_attempt {
                    Ok(v) => Ok(v),
                    Err(crate::daemon::DaemonClientError::Connect(_)) => {
                        // Neither socket is connectable.
                        //
                        // If the shared socket directory exists, assume this machine is configured
                        // for shared-daemon cross-user access and fail closed (do not autostart a
                        // per-user daemon under the caller).
                        if shared_socket.parent().map(|p| p.exists()).unwrap_or(false) {
                            return Err(format!(
                                "aivaultd not running at shared socket '{}' (start it as the operator with `aivaultd --shared`)",
                                shared_socket.display()
                            ));
                        }

                        // Otherwise, autostart per-user daemon if allowed.
                        autostart_and_retry(&user_socket).map_err(|e| {
                            format!(
                                "{e}\n(also tried shared socket '{}')",
                                shared_socket.display()
                            )
                        })
                    }
                    Err(crate::daemon::DaemonClientError::Protocol(err)) => Err(format!(
                        "invalid response from aivaultd at '{}': {}",
                        shared_socket.display(),
                        err
                    )),
                    Err(crate::daemon::DaemonClientError::Remote(err)) => Err(err),
                }
            }
            Err(crate::daemon::DaemonClientError::Protocol(err)) => Err(format!(
                "invalid response from aivaultd at '{}': {}",
                user_socket.display(),
                err
            )),
            Err(crate::daemon::DaemonClientError::Remote(err)) => Err(err),
        }
    }

    #[cfg(not(unix))]
    {
        // Non-unix targets: daemon boundary not supported; fall back to in-process.
        run_capability_envelope(vault, store, envelope, client_ip, workspace_id, group_id)
    }
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
    path_prefix_template: Option<String>,
    auth_headers: Vec<(String, String)>,
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
        AuthKind::Path => AuthStrategy::Path {
            prefix_template: options
                .path_prefix_template
                .unwrap_or_else(|| "/bot{{secret}}".to_string()),
        },
        AuthKind::Query => AuthStrategy::Query {
            param_name: options.query_param.unwrap_or_else(|| "api_key".to_string()),
        },
        AuthKind::MultiHeader => AuthStrategy::MultiHeader(
            options
                .auth_headers
                .into_iter()
                .map(
                    |(header_name, value_template)| crate::broker::AuthHeaderTemplate {
                        header_name,
                        value_template,
                    },
                )
                .collect(),
        ),
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

fn load_runtime_broker_for_context(
    vault: &VaultRuntime,
    store: &BrokerStore,
    requested_credential_id: Option<&str>,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<Broker, String> {
    #[cfg(not(debug_assertions))]
    {
        for var in [
            "AIVAULT_DEV_ALLOW_HTTP_LOCAL",
            "AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS",
            "AIVAULT_DEV_ALLOW_REMOTE_CLIENTS",
        ] {
            if std::env::var(var)
                .ok()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
            {
                return Err(format!(
                    "{} is disabled in release builds; unset it or use a debug build",
                    var
                ));
            }
        }
    }

    let mut cfg = BrokerConfig::default();
    if dev_flag_true("AIVAULT_DEV_ALLOW_HTTP_LOCAL") {
        cfg.allow_http_local_extension = true;
    }
    if dev_flag_true("AIVAULT_DEV_ALLOW_NON_DEFAULT_PORTS") {
        cfg.allow_non_default_ports_extension = true;
    }
    if dev_flag_true("AIVAULT_DEV_ALLOW_REMOTE_CLIENTS") {
        cfg.allow_remote_clients = true;
    }

    let registry = crate::registry::builtin_registry().map_err(|e| e.to_string())?;
    // Keep a copy to canonicalize any persisted (and thus potentially tamperable) broker store
    // entries back to the compiled-in registry policy.
    let registry_lookup = registry.clone();
    let mut broker = Broker::new(cfg, Some(registry));
    let operator = RequestAuth::Operator("operator-cli".to_string());
    let derived_registry_credentials = derive_registry_credentials_from_vault(vault, Some(store))?;
    let derived_registry_credential_ids: HashSet<String> = derived_registry_credentials
        .iter()
        .map(|credential| credential.id.clone())
        .collect();

    for stored in &derived_registry_credentials {
        if !credential_matches_context(stored, workspace_id, group_id) {
            continue;
        }

        let is_requested = requested_credential_id
            .map(|id| id.trim())
            .filter(|id| !id.is_empty())
            .is_some_and(|id| id == stored.id);

        let secret_id = match SecretRef::parse(&stored.secret_ref) {
            Ok(sr) => sr.secret_id,
            Err(err) => {
                if is_requested {
                    return Err(err);
                }
                continue;
            }
        };
        let secret_meta = match vault.get_secret_meta(&secret_id) {
            Ok(m) => m,
            Err(err) => {
                if is_requested {
                    return Err(err.to_string());
                }
                continue;
            }
        };
        if let Some(pinned) = secret_meta.pinned_provider.as_deref() {
            if pinned != stored.provider.as_str() {
                let msg = format!(
                    "credential '{}' provider '{}' cannot use secret pinned to provider '{}'",
                    stored.id, stored.provider, pinned
                );
                if is_requested {
                    return Err(msg);
                }
                continue;
            }
        }

        let secret = resolve_secret_ref_for_context(
            vault,
            &stored.secret_ref,
            workspace_id,
            group_id,
            Some("broker.credential.load"),
            Some("aivault-cli"),
        );
        let secret = match secret {
            Ok(secret) => secret,
            Err(err) => {
                if is_requested {
                    return Err(err);
                }
                continue;
            }
        };
        let secret = secret_material_from_bytes(&stored.auth, secret)?;

        let input = CredentialInput {
            id: stored.id.clone(),
            provider: stored.provider.clone(),
            // Registry-derived credentials are always canonicalized to registry auth.
            auth: None,
            // Hosts may be derived defaults or validated persisted overrides.
            hosts: Some(stored.hosts.clone()),
        };

        broker
            .create_credential(&operator, input, secret)
            .map_err(|e| e.to_string())?;
    }

    for stored in store.credentials() {
        if derived_registry_credential_ids.contains(&stored.id) {
            // Canonical registry credentials are derived from vault secrets at runtime.
            continue;
        }
        if !credential_matches_context(stored, workspace_id, group_id) {
            continue;
        }

        // A context-aware invoke should not fail closed just because an unrelated credential
        // isn't available in this context (e.g. global secret not attached to group).
        let is_requested = requested_credential_id
            .map(|id| id.trim())
            .filter(|id| !id.is_empty())
            .is_some_and(|id| id == stored.id);

        // Defense in depth: enforce registry-pinned secrets even if broker.json is tampered.
        let secret_id = match SecretRef::parse(&stored.secret_ref) {
            Ok(sr) => sr.secret_id,
            Err(err) => {
                if is_requested {
                    return Err(err);
                }
                continue;
            }
        };
        let secret_meta = match vault.get_secret_meta(&secret_id) {
            Ok(m) => m,
            Err(err) => {
                if is_requested {
                    return Err(err.to_string());
                }
                continue;
            }
        };
        if let Some(pinned) = secret_meta.pinned_provider.as_deref() {
            if pinned != stored.provider.as_str() {
                let msg = format!(
                    "credential '{}' provider '{}' cannot use secret pinned to provider '{}'",
                    stored.id, stored.provider, pinned
                );
                if is_requested {
                    return Err(msg);
                }
                continue;
            }

            let Some(provider_template) = registry_lookup.provider(pinned) else {
                let msg = format!(
                    "secret pinnedProvider '{}' requires registry provider template (missing)",
                    pinned
                );
                if is_requested {
                    return Err(msg);
                }
                continue;
            };

            if !stored.hosts.is_empty()
                && !stored.hosts.iter().all(|host| {
                    provider_template
                        .hosts
                        .iter()
                        .any(|pattern| crate::broker::host_matches(pattern, host))
                })
            {
                let msg = format!(
                    "credential '{}' hosts are not allowed by registry host policy for provider '{}'",
                    stored.id, pinned
                );
                if is_requested {
                    return Err(msg);
                }
                continue;
            }
        }

        let secret = resolve_secret_ref_for_context(
            vault,
            &stored.secret_ref,
            workspace_id,
            group_id,
            Some("broker.credential.load"),
            Some("aivault-cli"),
        );
        let secret = match secret {
            Ok(secret) => secret,
            Err(err) => {
                if is_requested {
                    return Err(err);
                }
                continue;
            }
        };
        let secret = secret_material_from_bytes(&stored.auth, secret)?;

        let registry_provider = registry_lookup.provider(&stored.provider).cloned();
        let is_registry_provider = registry_provider.is_some();
        // For registry-backed providers, ignore persisted auth overrides and re-derive from
        // compiled-in registry templates to prevent policy tampering via broker.json edits.
        let input = CredentialInput {
            id: stored.id.clone(),
            provider: stored.provider.clone(),
            auth: if is_registry_provider {
                None
            } else {
                Some(stored.auth.clone())
            },
            // Hosts are still credential-bound (per-tenant SaaS). For registry providers, only
            // accept host bindings that match the registry's allowed host patterns; otherwise
            // fail-open to canonical registry hosts (tamper resistance).
            hosts: if let Some(provider) = registry_provider.as_ref() {
                let allowed = !stored.hosts.is_empty()
                    && stored.hosts.iter().all(|host| {
                        provider
                            .hosts
                            .iter()
                            .any(|pattern| crate::broker::host_matches(pattern, host))
                    });
                allowed.then(|| stored.hosts.clone())
            } else {
                Some(stored.hosts.clone())
            },
        };

        broker
            .create_credential(&operator, input, secret)
            .map_err(|e| e.to_string())?;
    }

    for capability in store.capabilities() {
        if let Some(canonical) = registry_lookup.capability(&capability.id) {
            broker
                .upsert_capability(&operator, canonical)
                .map_err(|e| e.to_string())?;
            continue;
        }
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

fn resolve_secret_ref_for_context(
    vault: &VaultRuntime,
    secret_ref: &str,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
    capability: Option<&str>,
    consumer: Option<&str>,
) -> Result<Vec<u8>, String> {
    let ws = workspace_id.map(str::trim).filter(|v| !v.is_empty());
    let group_id = group_id.map(str::trim).filter(|v| !v.is_empty());
    if group_id.is_some() && ws.is_none() {
        return Err("--workspace-id is required when --group-id is provided".to_string());
    }
    if let Some(ws) = ws {
        let group_id = group_id
            .ok_or_else(|| "--group-id is required when --workspace-id is provided".to_string())?;
        return vault
            .resolve_secret_ref_for_group(secret_ref, ws, group_id, capability, consumer)
            .map_err(|e| e.to_string());
    }
    vault
        .resolve_secret_ref(secret_ref, capability, consumer)
        .map_err(|e| e.to_string())
}

fn credential_matches_context(
    credential: &StoredCredential,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> bool {
    let ws = workspace_id.map(str::trim).filter(|v| !v.is_empty());
    let group_id = group_id.map(str::trim).filter(|v| !v.is_empty());

    if group_id.is_some() && ws.is_none() {
        return false;
    }

    // When no context is provided, only global credentials are eligible.
    let cred_ws = credential
        .workspace_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let cred_group_id = credential
        .group_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());

    if ws.is_none() && group_id.is_none() {
        return cred_ws.is_none() && cred_group_id.is_none();
    }

    // Workspace-scoped credential: allow any group in the workspace.
    if let Some(cred_ws) = cred_ws {
        if ws != Some(cred_ws) {
            return false;
        }
        // Group-scoped credential: require exact match.
        if let Some(cred_group_id) = cred_group_id {
            return group_id == Some(cred_group_id);
        }
        return true;
    }

    // Global credential: eligible in any context (secret resolution will enforce attachments).
    true
}

fn env_flag_true(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[cfg(debug_assertions)]
fn dev_flag_true(name: &str) -> bool {
    env_flag_true(name)
}

#[cfg(not(debug_assertions))]
fn dev_flag_true(_name: &str) -> bool {
    false
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
        AuthStrategy::Header { .. } | AuthStrategy::Query { .. } | AuthStrategy::Path { .. } => {
            Ok(SecretMaterial::String(as_utf8()?))
        }
        AuthStrategy::MultiHeader(_) | AuthStrategy::MultiQuery(_) => {
            let label = if matches!(auth, AuthStrategy::MultiQuery(_)) {
                "multi-query"
            } else {
                "multi-header"
            };
            let value: serde_json::Value = serde_json::from_slice(&raw)
                .map_err(|_| format!("{} secret must be JSON", label))?;
            let obj = value
                .as_object()
                .ok_or_else(|| format!("{} secret must be a JSON object", label))?;
            let mut fields = HashMap::new();
            for (k, v) in obj {
                let k = k.trim();
                if k.is_empty() {
                    continue;
                }
                let Some(vs) = v.as_str() else {
                    return Err(format!(
                        "{} secret field '{}' must be a string value",
                        label, k
                    ));
                };
                fields.insert(k.to_string(), vs.to_string());
            }
            if fields.is_empty() {
                return Err(format!("{} secret must include at least one field", label));
            }
            Ok(SecretMaterial::Fields(fields))
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

    let safe_url = planned_url_for_output(broker, planned).unwrap_or_else(|_| {
        // Fail closed on secret disclosure; fall back to host-only URL.
        format!("{}://{}", planned.scheme, planned.host)
    });

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

    let response = req.send().map_err(|e| {
        // reqwest error strings often include the full URL. Replace any instance of the full URL
        // with the already-redacted planned URL to avoid leaking broker-managed secrets.
        let from = e
            .url()
            .map(|u| u.to_string())
            .unwrap_or_else(|| url.to_string());
        format_reqwest_error_with_url_replacement(&e, &from, &safe_url)
    })?;
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
            "url": safe_url
        },
        "response": {
            "status": forwarded.status,
            "headers": forwarded.headers,
            "bodyUtf8": body_utf8,
            "bodyB64": base64::engine::general_purpose::STANDARD.encode(body_raw)
        }
    }))
}

fn planned_url_for_output(broker: &Broker, planned: &PlannedRequest) -> Result<String, String> {
    let credential = broker
        .resolve_credential_for_capability(
            &planned.capability,
            Some(planned.credential.as_str()),
            Some(planned.credential.as_str()),
        )
        .map_err(|e| e.to_string())?;

    let mut safe_path = planned.path.clone();
    let mut safe_query = planned.query.clone();

    match &credential.auth {
        AuthStrategy::Query { param_name } => {
            for (k, v) in safe_query.iter_mut() {
                if k == param_name {
                    *v = "REDACTED".to_string();
                }
            }
        }
        AuthStrategy::MultiQuery(templates) => {
            for template in templates {
                for (k, v) in safe_query.iter_mut() {
                    if k == &template.param_name {
                        *v = "REDACTED".to_string();
                    }
                }
            }
        }
        AuthStrategy::Path { prefix_template } => {
            let static_prefix = prefix_template
                .split("{{secret}}")
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            if !static_prefix.is_empty() && safe_path.starts_with(static_prefix.as_str()) {
                let after = &safe_path[static_prefix.len()..];
                if let Some(idx) = after.find('/') {
                    safe_path = format!("{}REDACTED{}", static_prefix, &after[idx..]);
                } else {
                    safe_path = format!("{}REDACTED", static_prefix);
                }
            } else {
                safe_path = "/REDACTED".to_string();
            }
        }
        _ => {}
    }

    let mut safe_url = reqwest::Url::parse(&format!(
        "{}://{}{}",
        planned.scheme, planned.host, safe_path
    ))
    .map_err(|e| e.to_string())?;
    {
        let mut qp = safe_url.query_pairs_mut();
        for (k, v) in safe_query {
            qp.append_pair(&k, &v);
        }
    }
    Ok(safe_url.to_string())
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

fn format_reqwest_error_with_url_replacement(
    error: &reqwest::Error,
    from: &str,
    to: &str,
) -> String {
    let mut message = error.to_string().replace(from, to);
    let mut current: Option<&(dyn std::error::Error + 'static)> = error.source();
    while let Some(source) = current {
        message.push_str(": ");
        message.push_str(&source.to_string().replace(from, to));
        current = source.source();
    }
    message
}

fn build_http_client_with_dev_overrides() -> Result<Client, String> {
    let mut builder = Client::builder().redirect(RedirectPolicy::none());

    #[cfg(not(debug_assertions))]
    {
        // Dev-only escape hatches are disabled in release builds. If any are set, fail clearly
        // rather than silently ignoring them.
        for var in [
            "AIVAULT_DEV_HTTP1_ONLY",
            "AIVAULT_DEV_CA_CERT_PATH",
            "AIVAULT_DEV_RESOLVE",
        ] {
            if std::env::var(var)
                .ok()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
            {
                return Err(format!(
                    "{} is disabled in release builds; unset it or use a debug build",
                    var
                ));
            }
        }
    }

    if dev_flag_true("AIVAULT_DEV_HTTP1_ONLY") {
        builder = builder.http1_only();
    }

    #[cfg(debug_assertions)]
    {
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

fn parse_secret_scope(
    scope: ScopeKind,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<SecretScope, String> {
    match scope {
        ScopeKind::Global => Ok(SecretScope::Global),
        ScopeKind::Workspace => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            Ok(SecretScope::Workspace {
                workspace_id: workspace_id.to_string(),
            })
        }
        ScopeKind::Group => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            let group_id = required_arg("group-id", group_id)?;
            Ok(SecretScope::Group {
                workspace_id: workspace_id.to_string(),
                group_id: group_id.to_string(),
            })
        }
    }
}

fn parse_capability_scope(
    scope: ScopeKind,
    workspace_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<CapabilityScope, String> {
    match scope {
        ScopeKind::Global => Ok(CapabilityScope::Global),
        ScopeKind::Workspace => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            Ok(CapabilityScope::Workspace {
                workspace_id: workspace_id.to_string(),
            })
        }
        ScopeKind::Group => {
            let workspace_id = required_arg("workspace-id", workspace_id)?;
            let group_id = required_arg("group-id", group_id)?;
            Ok(CapabilityScope::Group {
                workspace_id: workspace_id.to_string(),
                group_id: group_id.to_string(),
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
    group_id: Option<&str>,
) -> bool {
    match requested {
        ScopeKind::Global => matches!(scope, SecretScope::Global),
        ScopeKind::Workspace => matches!(
            scope,
            SecretScope::Workspace {
                workspace_id: ws
            } if Some(ws.as_str()) == workspace_id.map(str::trim)
        ),
        ScopeKind::Group => matches!(
            scope,
            SecretScope::Group {
                workspace_id: ws,
                group_id: g
            } if Some(ws.as_str()) == workspace_id.map(str::trim)
                && Some(g.as_str()) == group_id.map(str::trim)
        ),
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    println!("{}", raw);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(not(debug_assertions))]
    use super::build_http_client_with_dev_overrides;
    use super::{build_oauth_setup_plan, load_runtime_broker_for_context};
    use crate::broker::{AuthStrategy, ProxyEnvelope, ProxyEnvelopeRequest, ProxyTokenMintRequest};
    use crate::broker_store::{BrokerStore, StoredCredential};
    use crate::cli::{CapabilityCommand, CredentialCommand, ScopeKind, SecretsCommand};
    use crate::test_support::{ScopedEnvVar, ENV_LOCK};
    use crate::vault::{SecretRef, SecretScope, VaultProviderConfig, VaultRuntime};
    use base64::Engine;
    use std::collections::HashMap;
    use std::net::IpAddr;

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

    #[test]
    #[cfg(not(debug_assertions))]
    fn release_rejects_dev_http_client_overrides() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _var = ScopedEnvVar::set("AIVAULT_DEV_HTTP1_ONLY", "1");
        let err = build_http_client_with_dev_overrides().unwrap_err();
        assert!(err.contains("disabled in release builds"));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn release_rejects_dev_broker_escape_hatches() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = [7u8; 32];
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        let _var = ScopedEnvVar::set("AIVAULT_DEV_ALLOW_REMOTE_CLIENTS", "1");
        let err = load_runtime_broker_for_context(&vault, &store, None, None, None).unwrap_err();
        assert!(err.contains("disabled in release builds"));
    }

    #[test]
    fn multi_header_secret_parses_as_fields() {
        let auth = AuthStrategy::MultiHeader(vec![crate::broker::AuthHeaderTemplate {
            header_name: "x-api-key".to_string(),
            value_template: "{{api_key}}".to_string(),
        }]);
        let raw = br#"{"api_key":"k1","app_key":"k2"}"#.to_vec();
        let parsed =
            super::secret_material_from_bytes(&auth, raw).expect("secret parse should work");
        let crate::broker::SecretMaterial::Fields(fields) = parsed else {
            panic!("expected SecretMaterial::Fields");
        };
        assert_eq!(fields.get("api_key").map(String::as_str), Some("k1"));
        assert_eq!(fields.get("app_key").map(String::as_str), Some("k2"));
    }

    #[test]
    fn invoke_context_skips_unattached_global_credentials_unless_requested() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = [7u8; 32];
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("GLOBAL_TOKEN", b"t-1", SecretScope::Global, vec![])
            .unwrap();
        let secret_ref = SecretRef {
            secret_id: meta.secret_id.clone(),
        }
        .to_string();

        let mut store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        store.upsert_credential(StoredCredential {
            id: "openai".to_string(),
            provider: "openai".to_string(),
            workspace_id: None,
            group_id: None,
            auth: AuthStrategy::Header {
                header_name: "authorization".to_string(),
                value_template: "Bearer {{secret}}".to_string(),
            },
            hosts: vec!["api.openai.com".to_string()],
            secret_ref,
        });

        let broker =
            load_runtime_broker_for_context(&vault, &store, None, Some("default"), Some("dev"))
                .unwrap();
        assert!(broker.credentials().is_empty());

        assert!(load_runtime_broker_for_context(
            &vault,
            &store,
            Some("openai"),
            Some("default"),
            Some("dev")
        )
        .is_err());

        vault
            .attach_secret_to_group(&meta.secret_id, "default", "dev")
            .unwrap();
        let broker =
            load_runtime_broker_for_context(&vault, &store, None, Some("default"), Some("dev"))
                .unwrap();
        assert_eq!(broker.credentials().len(), 1);
    }

    #[test]
    fn workspace_scoped_credentials_require_matching_workspace_and_group_context() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = [7u8; 32];
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret(
                "WORKSPACE_TOKEN",
                b"w-1",
                SecretScope::Workspace {
                    workspace_id: "default".to_string(),
                },
                vec![],
            )
            .unwrap();
        let secret_ref = SecretRef {
            secret_id: meta.secret_id,
        }
        .to_string();

        let mut store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        store.upsert_credential(StoredCredential {
            id: "ws-cred".to_string(),
            provider: "openai".to_string(),
            workspace_id: Some("default".to_string()),
            group_id: None,
            auth: AuthStrategy::Header {
                header_name: "authorization".to_string(),
                value_template: "Bearer {{secret}}".to_string(),
            },
            hosts: vec!["api.openai.com".to_string()],
            secret_ref,
        });

        let broker = load_runtime_broker_for_context(&vault, &store, None, None, None).unwrap();
        assert!(broker.credentials().is_empty());

        let broker =
            load_runtime_broker_for_context(&vault, &store, None, Some("other"), Some("dev"))
                .unwrap();
        assert!(broker.credentials().is_empty());

        let broker =
            load_runtime_broker_for_context(&vault, &store, None, Some("default"), Some("support"))
                .unwrap();
        assert_eq!(broker.credentials().len(), 1);
    }

    #[test]
    fn registry_policy_is_canonical_and_not_overridable_by_broker_store() {
        let _lock = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let _vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = [7u8; 32];
        let _vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();

        let meta = vault
            .create_secret("OPENAI_TOKEN", b"t-1", SecretScope::Global, vec![])
            .unwrap();
        let secret_ref = SecretRef {
            secret_id: meta.secret_id.clone(),
        }
        .to_string();

        let mut store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        // Persisted broker state is treated as untrusted input at runtime: registry-backed
        // credentials and capabilities must be canonicalized back to compiled-in policy.
        store.upsert_credential(StoredCredential {
            id: "openai".to_string(),
            provider: "openai".to_string(),
            workspace_id: None,
            group_id: None,
            // Tampered auth/hosts (should be ignored for registry providers).
            auth: AuthStrategy::Query {
                param_name: "api_key".to_string(),
            },
            hosts: vec!["evil.example".to_string()],
            secret_ref,
        });
        store.upsert_capability(crate::broker::Capability {
            id: "openai/transcription".to_string(),
            provider: "openai".to_string(),
            allow: crate::broker::AllowPolicy {
                hosts: vec!["evil.example".to_string()],
                methods: vec!["POST".to_string()],
                path_prefixes: vec!["/evil".to_string()],
            },
        });

        let mut broker = load_runtime_broker_for_context(&vault, &store, None, None, None).unwrap();

        let cap = broker
            .capabilities()
            .into_iter()
            .find(|c| c.id == "openai/transcription")
            .unwrap();
        assert_eq!(cap.allow.hosts, vec!["api.openai.com"]);
        assert_eq!(cap.allow.path_prefixes, vec!["/v1/audio/transcriptions"]);

        let cred = broker
            .credentials()
            .into_iter()
            .find(|c| c.id == "openai")
            .unwrap();
        assert_eq!(cred.hosts, vec!["api.openai.com"]);

        let token = broker
            .mint_proxy_token(
                &crate::broker::RequestAuth::Operator("test".to_string()),
                ProxyTokenMintRequest {
                    capabilities: vec!["openai/transcription".to_string()],
                    credential: Some("openai".to_string()),
                    ttl_ms: 60_000,
                    context: HashMap::new(),
                },
            )
            .unwrap();

        let envelope = ProxyEnvelope {
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
        };

        let planned = broker
            .execute_envelope(
                &crate::broker::RequestAuth::Proxy(token.token),
                envelope,
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            )
            .unwrap();
        assert_eq!(planned.host, "api.openai.com");
    }

    fn init_test_vault() -> (tempfile::TempDir, VaultRuntime, ScopedEnvVar, ScopedEnvVar) {
        let tmp = tempfile::tempdir().unwrap();
        let vault_dir = ScopedEnvVar::set("AIVAULT_DIR", tmp.path());
        let key = [7u8; 32];
        let vault_key = ScopedEnvVar::set(
            "AIVAULT_KEY",
            base64::engine::general_purpose::STANDARD.encode(key),
        );

        let vault = VaultRuntime::discover();
        vault.load().unwrap();
        vault
            .init(VaultProviderConfig::Env {
                env_var: "AIVAULT_KEY".to_string(),
            })
            .unwrap();
        (tmp, vault, vault_dir, vault_key)
    }

    #[test]
    fn secrets_create_pins_registry_claim_and_autoprovisions_single_secret_credential() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();

        super::run_secrets(
            &vault,
            SecretsCommand::Create {
                name: "OPENAI_API_KEY".to_string(),
                value: "sk-test".to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                alias: Vec::new(),
            },
        )
        .unwrap();

        let secrets = vault.list_secrets().unwrap();
        let meta = secrets
            .into_iter()
            .find(|m| m.name == "OPENAI_API_KEY")
            .expect("secret should exist");
        assert_eq!(meta.pinned_provider.as_deref(), Some("openai"));

        let store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        let cred = store
            .credentials()
            .iter()
            .find(|c| c.id == "openai")
            .expect("credential should be auto-provisioned");
        assert_eq!(cred.provider, "openai");
        assert_eq!(
            cred.secret_ref,
            SecretRef {
                secret_id: meta.secret_id
            }
            .to_string()
        );
    }

    #[test]
    fn secrets_create_autoprovisions_multi_secret_registry_credential_via_composite_secret() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();

        super::run_secrets(
            &vault,
            SecretsCommand::Create {
                name: "TRELLO_API_KEY".to_string(),
                value: "k-1".to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                alias: Vec::new(),
            },
        )
        .unwrap();
        // Not complete yet: no credential.
        let store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        assert!(store.credentials().iter().all(|c| c.id != "trello"));

        super::run_secrets(
            &vault,
            SecretsCommand::Create {
                name: "TRELLO_TOKEN".to_string(),
                value: "t-1".to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                alias: Vec::new(),
            },
        )
        .unwrap();

        let secrets = vault.list_secrets().unwrap();
        let api_key = secrets.iter().find(|m| m.name == "TRELLO_API_KEY").unwrap();
        let token = secrets.iter().find(|m| m.name == "TRELLO_TOKEN").unwrap();
        assert_eq!(api_key.pinned_provider.as_deref(), Some("trello"));
        assert_eq!(token.pinned_provider.as_deref(), Some("trello"));

        let store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        let cred = store
            .credentials()
            .iter()
            .find(|c| c.id == "trello")
            .expect("trello credential should be auto-provisioned");

        let composite_sr = SecretRef::parse(&cred.secret_ref).unwrap();
        let composite_meta = vault.get_secret_meta(&composite_sr.secret_id).unwrap();
        assert!(composite_meta.system_managed);
        assert_eq!(composite_meta.pinned_provider.as_deref(), Some("trello"));

        let raw = vault
            .resolve_secret_ref(&cred.secret_ref, Some("test"), Some("test"))
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v.get("key").and_then(|x| x.as_str()), Some("k-1"));
        assert_eq!(v.get("token").and_then(|x| x.as_str()), Some("t-1"));
    }

    #[test]
    fn secrets_import_reconciles_existing_registry_credential_secret_binding() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();

        super::run_secrets(
            &vault,
            SecretsCommand::Create {
                name: "OPENAI_API_KEY".to_string(),
                value: "sk-initial".to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                alias: Vec::new(),
            },
        )
        .unwrap();

        let openai_secret = vault
            .list_secrets()
            .unwrap()
            .into_iter()
            .find(|m| m.name == "OPENAI_API_KEY")
            .expect("openai secret should exist");

        let mut store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        let mut tampered = store
            .credentials()
            .iter()
            .find(|c| c.id == "openai")
            .cloned()
            .expect("openai credential should be auto-provisioned");
        tampered.secret_ref = "vault:secret:missing-secret-id".to_string();
        store.upsert_credential(tampered);
        store.save().unwrap();

        // Canonical runtime resolution derives registry credentials from vault secrets, so the
        // stale persisted secretRef does not break invocation.
        let broker = load_runtime_broker_for_context(&vault, &store, None, None, None).unwrap();
        assert!(broker.credentials().iter().any(|c| c.id == "openai"));

        super::run_secrets(
            &vault,
            SecretsCommand::Import {
                entry: vec!["OPENAI_API_KEY=sk-rotated".to_string()],
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
            },
        )
        .unwrap();

        let repaired_store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        let repaired = repaired_store
            .credentials()
            .iter()
            .find(|c| c.id == "openai")
            .expect("openai credential should still exist");
        assert_eq!(
            repaired.secret_ref,
            SecretRef {
                secret_id: openai_secret.secret_id
            }
            .to_string()
        );

        let broker =
            load_runtime_broker_for_context(&vault, &repaired_store, None, None, None).unwrap();
        assert!(broker.credentials().iter().any(|c| c.id == "openai"));
    }

    #[test]
    fn runtime_derives_registry_credentials_from_vault_when_store_is_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();

        let meta = vault
            .create_secret("OPENAI_API_KEY", b"sk-direct", SecretScope::Global, vec![])
            .unwrap();
        let _ = vault
            .pin_secret_to_provider(&meta.secret_id, "openai")
            .unwrap();

        let store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        assert!(store.credentials().is_empty());

        let mut broker = load_runtime_broker_for_context(&vault, &store, None, None, None).unwrap();
        assert!(broker.credentials().iter().any(|c| c.id == "openai"));

        let token = broker
            .mint_proxy_token(
                &crate::broker::RequestAuth::Operator("test".to_string()),
                ProxyTokenMintRequest {
                    capabilities: vec!["openai/transcription".to_string()],
                    credential: Some("openai".to_string()),
                    ttl_ms: 60_000,
                    context: HashMap::new(),
                },
            )
            .unwrap();

        let envelope = ProxyEnvelope {
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
        };
        let planned = broker
            .execute_envelope(
                &crate::broker::RequestAuth::Proxy(token.token),
                envelope,
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            )
            .unwrap();
        assert_eq!(planned.credential, "openai");
        assert_eq!(planned.host, "api.openai.com");
    }

    #[test]
    fn credential_create_rejects_provider_mismatch_for_pinned_secret() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();

        super::run_secrets(
            &vault,
            SecretsCommand::Create {
                name: "OPENAI_API_KEY".to_string(),
                value: "sk-test".to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                alias: Vec::new(),
            },
        )
        .unwrap();
        let meta = vault
            .list_secrets()
            .unwrap()
            .into_iter()
            .find(|m| m.name == "OPENAI_API_KEY")
            .unwrap();

        let err = super::run_credential(
            &vault,
            CredentialCommand::Create {
                id: "evil".to_string(),
                provider: "github".to_string(),
                secret_ref: SecretRef {
                    secret_id: meta.secret_id,
                }
                .to_string(),
                workspace_id: None,
                group_id: None,
                auth: None,
                host: Vec::new(),
                header_name: None,
                value_template: None,
                query_param: None,
                grant_type: None,
                token_endpoint: None,
                scope: Vec::new(),
                aws_service: None,
                aws_region: None,
                hmac_algorithm: None,
                path_prefix_template: None,
                auth_header: Vec::new(),
            },
        )
        .unwrap_err();
        assert!(err.contains("pinned"));
    }

    #[test]
    fn runtime_credential_loading_skips_or_errors_on_pinned_secret_provider_mismatch() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();

        super::run_secrets(
            &vault,
            SecretsCommand::Create {
                name: "OPENAI_API_KEY".to_string(),
                value: "sk-test".to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                alias: Vec::new(),
            },
        )
        .unwrap();
        let meta = vault
            .list_secrets()
            .unwrap()
            .into_iter()
            .find(|m| m.name == "OPENAI_API_KEY")
            .unwrap();

        let mut store = BrokerStore::open_under(vault.paths().root_dir()).unwrap();
        store.upsert_credential(StoredCredential {
            id: "evil".to_string(),
            provider: "github".to_string(),
            workspace_id: None,
            group_id: None,
            auth: AuthStrategy::Header {
                header_name: "authorization".to_string(),
                value_template: "Bearer {{secret}}".to_string(),
            },
            hosts: vec!["api.github.com".to_string()],
            secret_ref: SecretRef {
                secret_id: meta.secret_id,
            }
            .to_string(),
        });

        // Not requested: invalid credential should be skipped (other valid credentials may load).
        let broker = load_runtime_broker_for_context(&vault, &store, None, None, None).unwrap();
        assert!(broker.credentials().iter().all(|c| c.id != "evil"));

        // Requested: fail closed.
        assert!(load_runtime_broker_for_context(&vault, &store, Some("evil"), None, None).is_err());
    }

    #[test]
    fn capabilities_bind_rejects_pinned_secret_provider_mismatch() {
        let _lock = ENV_LOCK.lock().unwrap();
        let (_tmp, vault, _vault_dir, _vault_key) = init_test_vault();

        super::run_secrets(
            &vault,
            SecretsCommand::Create {
                name: "OPENAI_API_KEY".to_string(),
                value: "sk-test".to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                alias: Vec::new(),
            },
        )
        .unwrap();

        let meta = vault
            .list_secrets()
            .unwrap()
            .into_iter()
            .find(|m| m.name == "OPENAI_API_KEY")
            .unwrap();

        let err = super::run_capability(
            &vault,
            CapabilityCommand::Bind {
                capability: "github/repos".to_string(),
                secret_ref: SecretRef {
                    secret_id: meta.secret_id,
                }
                .to_string(),
                scope: ScopeKind::Global,
                workspace_id: None,
                group_id: None,
                consumer: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("pinned"));
    }

    #[test]
    fn planned_url_redacts_query_auth_secret_values() {
        let mut broker = crate::broker::Broker::default_with_registry(None);
        let op = crate::broker::RequestAuth::Operator("test".to_string());
        broker
            .create_credential(
                &op,
                crate::broker::CredentialInput {
                    id: "legacy".to_string(),
                    provider: "legacy".to_string(),
                    auth: Some(crate::broker::AuthStrategy::Query {
                        param_name: "api_key".to_string(),
                    }),
                    hosts: Some(vec!["postman-echo.com".to_string()]),
                },
                crate::broker::SecretMaterial::String("super-secret".to_string()),
            )
            .unwrap();
        broker
            .create_capability(
                &op,
                crate::broker::Capability {
                    id: "legacy/get".to_string(),
                    provider: "legacy".to_string(),
                    allow: crate::broker::AllowPolicy {
                        hosts: vec!["postman-echo.com".to_string()],
                        methods: vec!["GET".to_string()],
                        path_prefixes: vec!["/get".to_string()],
                    },
                },
            )
            .unwrap();

        let token = broker
            .mint_proxy_token(
                &op,
                crate::broker::ProxyTokenMintRequest {
                    capabilities: vec!["legacy/get".to_string()],
                    credential: Some("legacy".to_string()),
                    ttl_ms: 60_000,
                    context: HashMap::new(),
                },
            )
            .unwrap();

        let planned = broker
            .execute_envelope(
                &crate::broker::RequestAuth::Proxy(token.token),
                crate::broker::ProxyEnvelope {
                    capability: "legacy/get".to_string(),
                    credential: Some("legacy".to_string()),
                    request: crate::broker::ProxyEnvelopeRequest {
                        method: "GET".to_string(),
                        path: "/get?x=1".to_string(),
                        headers: Vec::new(),
                        body: None,
                        multipart: None,
                        multipart_files: Vec::new(),
                        body_file_path: None,
                        url: None,
                    },
                },
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            )
            .unwrap();

        let safe = super::planned_url_for_output(&broker, &planned).unwrap();
        assert!(!safe.contains("super-secret"));
        assert!(safe.contains("api_key=REDACTED"));
    }

    #[test]
    fn planned_url_redacts_path_auth_secret_values() {
        let mut broker = crate::broker::Broker::default_with_registry(None);
        let op = crate::broker::RequestAuth::Operator("test".to_string());
        broker
            .create_credential(
                &op,
                crate::broker::CredentialInput {
                    id: "tg".to_string(),
                    provider: "telegram".to_string(),
                    auth: Some(crate::broker::AuthStrategy::Path {
                        prefix_template: "/bot{{secret}}".to_string(),
                    }),
                    hosts: Some(vec!["api.telegram.org".to_string()]),
                },
                crate::broker::SecretMaterial::String("token-123".to_string()),
            )
            .unwrap();
        broker
            .create_capability(
                &op,
                crate::broker::Capability {
                    id: "telegram/getme".to_string(),
                    provider: "telegram".to_string(),
                    allow: crate::broker::AllowPolicy {
                        hosts: vec!["api.telegram.org".to_string()],
                        methods: vec!["GET".to_string()],
                        path_prefixes: vec!["/getMe".to_string()],
                    },
                },
            )
            .unwrap();

        let token = broker
            .mint_proxy_token(
                &op,
                crate::broker::ProxyTokenMintRequest {
                    capabilities: vec!["telegram/getme".to_string()],
                    credential: Some("tg".to_string()),
                    ttl_ms: 60_000,
                    context: HashMap::new(),
                },
            )
            .unwrap();

        let planned = broker
            .execute_envelope(
                &crate::broker::RequestAuth::Proxy(token.token),
                crate::broker::ProxyEnvelope {
                    capability: "telegram/getme".to_string(),
                    credential: Some("tg".to_string()),
                    request: crate::broker::ProxyEnvelopeRequest {
                        method: "GET".to_string(),
                        path: "/getMe".to_string(),
                        headers: Vec::new(),
                        body: None,
                        multipart: None,
                        multipart_files: Vec::new(),
                        body_file_path: None,
                        url: None,
                    },
                },
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            )
            .unwrap();

        // Planned path includes the real token (used for execution), but the display URL must not.
        assert!(planned.path.contains("token-123"));
        let safe = super::planned_url_for_output(&broker, &planned).unwrap();
        assert!(!safe.contains("token-123"));
        assert!(safe.contains("REDACTED"));
    }
}
