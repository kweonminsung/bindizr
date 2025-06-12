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

async fn bootstrap() -> Result<(), String> {
    init_logger();
    init_subsystems();

    serializer::initialize();
    api::initialize().await;

    Ok(())
}

pub async fn execute(args: &Args) {
    config::initialize();

    const SUPPORTED_COMMANDS: [&str; 6] = ["start", "stop", "status", "dns", "token", "bootstrap"];

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
        "bootstrap" => bootstrap().await,
        _ => Ok(()),
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
