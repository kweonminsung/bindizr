mod api;
mod cli;
mod config;
mod database;
mod rndc;
mod serializer;

use rndc::RndcClient;
use serializer::SERIALIZER;
use std::process::exit;

async fn bootstrap() {
    // Maintain initialization order
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
        "start" => {
            if args.foreground {
                bootstrap().await;
            } else {
                platform::start();
            }
        }
        "stop" => platform::stop(),
        "reload" => {
            SERIALIZER.send_message("write_config");

            RndcClient::command("reload").expect("Failed to reload DNS configuration");
        }
        "bootstrap" => bootstrap().await,
        _ => {
            eprintln!("Unsupported command: {}", args.command);
            exit(1);
        }
    }
}
