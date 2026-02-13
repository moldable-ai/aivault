use clap::Parser;

fn main() {
    let cli = aivault::cli::Cli::parse();
    if let Err(err) = aivault::app::run(cli) {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
