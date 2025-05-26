mod api;
mod cli;
mod config;
mod database;
mod rndc;
mod serializer;

use std::process::exit;

async fn bootstrap() {
    // Initialize components
    config::initialize();
    database::initialize();
    serializer::initialize();
    api::initialize().await;
}

#[tokio::main]
async fn main() {
    #[cfg(not(any(windows, unix)))]
    {
        eprintln!("Unsupported platform. Only Windows and Unix-like systems are supported");
        exit(1);
    }

    // Process command line arguments
    let args = cli::Args::process_args();

    // Execute command
    match args.command.as_str() {
        "start" => cli::start::execute(&args).await,
        "stop" => cli::stop::execute(&args),
        "reload" => cli::reload::execute(&args),
        "token" => {
            if let Err(e) =
                cli::token::handle_command(args.subcommand.as_deref(), &args.subcommand_args)
            {
                eprintln!("Error: {}", e);
                exit(1);
            }
        }
        "bootstrap" => bootstrap().await,
        _ => {
            eprintln!("Unsupported command: {}", args.command);
            exit(1);
        }
    }
}
