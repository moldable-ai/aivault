use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "aivaultd")]
#[command(about = "Local broker daemon for aivault (unix socket)")]
struct Args {
    /// Unix socket path to listen on.
    #[arg(long)]
    socket: Option<String>,

    /// Listen on the well-known shared socket path and relax permissions for group access.
    ///
    /// This is intended for cross-user invocation on the same machine (operator runs the daemon,
    /// untrusted agents connect via the unix socket without ever seeing secrets).
    #[arg(long)]
    shared: bool,

    /// Serve a single request then exit (useful for tests).
    #[arg(long)]
    once: bool,
}

fn main() {
    let args = Args::parse();
    if args.shared {
        // Sugar for shared socket permissions. Operators can still override via env vars.
        if std::env::var("AIVAULTD_SOCKET_DIR_MODE")
            .ok()
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
        {
            std::env::set_var("AIVAULTD_SOCKET_DIR_MODE", "0750");
        }
        if std::env::var("AIVAULTD_SOCKET_MODE")
            .ok()
            .map(|v| v.trim().is_empty())
            .unwrap_or(true)
        {
            std::env::set_var("AIVAULTD_SOCKET_MODE", "0660");
        }
    }
    let socket_path = args
        .socket
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            if args.shared {
                aivault::daemon::shared_socket_path()
            } else {
                aivault::daemon::default_socket_path()
            }
        });

    if let Err(err) = aivault::daemon::serve(&socket_path, args.once) {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
