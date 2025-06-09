pub mod daemon;
pub mod dns;
pub mod parser;
pub mod start;
pub mod stop;
pub mod token;

use crate::{api, config, database, logger, serializer};
use parser::Args;

fn pre_bootstrap(skip_logger_init: bool, skip_database_init: bool) {
    config::initialize();

    if !skip_logger_init {
        logger::initialize();
    }

    if !skip_database_init {
        database::initialize();
    }
}

async fn bootstrap() {
    serializer::initialize();
    api::initialize().await;
}

pub async fn execute(args: &Args) {
    match args.command.as_str() {
        "start" | "stop" => pre_bootstrap(true, true),
        "dns" | "token" => pre_bootstrap(true, false),
        "bootstrap" => pre_bootstrap(false, false),
        _ => {
            eprintln!("Unsupported command: {}", args.command);
            std::process::exit(1);
        }
    }

    // Execute command
    match args.command.as_str() {
        "start" => start::execute(args).await,
        "stop" => stop::execute(args),
        "dns" => {
            if let Err(e) = dns::handle_command(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        "token" => {
            if let Err(e) = token::handle_command(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        "bootstrap" => bootstrap().await,
        _ => {}
    }
}
