use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "aivaultd")]
#[command(about = "Local broker daemon for aivault (unix socket)")]
struct Args {
    /// Unix socket path to listen on.
    #[arg(long)]
    socket: Option<String>,

    /// Serve a single request then exit (useful for tests).
    #[arg(long)]
    once: bool,
}

fn main() {
    let args = Args::parse();
    let socket_path = args
        .socket
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(aivault::daemon::default_socket_path);

    if let Err(err) = aivault::daemon::serve(&socket_path, args.once) {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
