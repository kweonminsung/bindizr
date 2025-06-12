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

pub fn init_subsystems() {
    database::initialize();
    rndc::initialize();
}

pub async fn bootstrap() -> Result<(), String> {
    logger::initialize();

    init_subsystems();

    serializer::initialize();
    api::initialize().await;

    Ok(())
}

pub async fn execute(args: &Args) {
    if !SUPPORTED_COMMANDS.contains(&args.command.as_str()) {
        eprintln!("Unsupported command: {}", args.command);
        std::process::exit(1);
    }

    // Initialize Configuration
    if args.has_option("-c") || args.has_option("--config") {
        // Load configuration from the specified file
        let config_file = args
            .get_option_value("-c")
            .or_else(|| args.get_option_value("--config"));
        if let Some(file) = config_file {
            config::initialize_from_file(file);
        } else {
            eprintln!("Configuration file not specified");
            std::process::exit(1);
        }
    } else {
        // Use default configuration file
        config::initialize();
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
