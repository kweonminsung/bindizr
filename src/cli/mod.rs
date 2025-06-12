pub mod daemon;
pub mod dns;
pub mod parser;
pub mod start;
pub mod status;
pub mod stop;
pub mod token;

use crate::{api, config, database, logger, rndc, serializer};
use parser::Args;

fn init_logger() {
    logger::initialize();
}

fn init_subsystems() {
    database::initialize();
    rndc::initialize();
}

async fn bootstrap() {
    serializer::initialize();
    api::initialize().await;
}

pub async fn execute(args: &Args) {
    config::initialize();

    match args.command.as_str() {
        "stop" | "status" => {}
        "dns" | "token" => init_subsystems(),
        "start" | "bootstrap" => {
            init_logger();
            init_subsystems();
        }
        _ => {
            eprintln!("Unsupported command: {}", args.command);
            std::process::exit(1);
        }
    }

    // Execute command
    match args.command.as_str() {
        "start" => start::execute(args).await,
        "stop" => stop::execute(),
        "status" => status::execute(),
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
