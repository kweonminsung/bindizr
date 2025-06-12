pub mod daemon;
mod dns;
mod help;
pub mod parser;
mod start;
mod status;
mod stop;
mod token;

use crate::{api, config, database, logger, rndc, serializer};
use parser::Args;

pub const SUPPORTED_COMMANDS: [&str; 7] = [
    "start",
    "stop",
    "status",
    "dns",
    "token",
    "bootstrap",
    "help",
];

fn init_logger() {
    logger::initialize();
}

fn init_subsystems() {
    database::initialize();
    rndc::initialize();
}

async fn bootstrap() -> Result<(), String> {
    init_logger();
    init_subsystems();

    serializer::initialize();
    api::initialize().await;

    Ok(())
}

pub async fn execute(args: &Args) {
    config::initialize();

    if !SUPPORTED_COMMANDS.contains(&args.command.as_str()) {
        eprintln!("Unsupported command: {}", args.command);
        std::process::exit(1);
    }

    // Execute command
    if let Err(e) = match args.command.as_str() {
        "start" => start::handle_command(args).await,
        "stop" => stop::handle_command(),
        "status" => status::handle_command(),
        "dns" => dns::handle_command(args),
        "token" => token::handle_command(args),
        "help" => help::handle_command(),
        "bootstrap" => bootstrap().await,
        _ => Ok(()),
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
