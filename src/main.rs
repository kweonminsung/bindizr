mod api;
mod cli;
mod config;
mod database;
mod rndc;
mod serializer;

use cli::{execute, parser::Args};

async fn bootstrap() {
    serializer::initialize();
    api::initialize().await;
}

#[tokio::main]
async fn main() {
    #[cfg(not(any(windows, unix)))]
    {
        eprintln!("Unsupported platform. Only Windows and Unix-like systems are supported");
        std::process::exit(1);
    }

    // Process command line arguments
    let args = Args::process_args();

    if args.command.as_str() == "bootstrap" {
        return bootstrap().await;
    }

    execute(&args).await;
}
