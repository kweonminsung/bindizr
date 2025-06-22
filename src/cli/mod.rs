pub mod parser;

mod dns;
mod help;
mod start;
mod status;
mod stop;
mod token;

use crate::{api, config, daemon, database, logger, rndc, serializer};
use parser::Args;

pub const SUPPORTED_COMMANDS: [&str; 6] = ["start", "stop", "status", "dns", "token", "help"];

pub async fn bootstrap(is_daemon: bool, config_file: Option<&str>) -> Result<(), String> {
    // Initialize Configuration
    if let Some(file) = config_file {
        // Load configuration from the specified file
        config::initialize_from_file(file);
    } else {
        // Use default configuration file
        config::initialize();
    }

    logger::initialize(is_daemon);
    database::initialize();
    rndc::initialize();
    serializer::initialize();

    daemon::socket::server::initialize()?;
    api::initialize().await?;

    Ok(())
}

pub async fn execute(args: &Args) {
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
        _ => Ok(()),
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
