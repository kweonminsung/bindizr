mod dns;
mod start;
mod status;
mod stop;
mod token;

use crate::{
    api,
    cli::{dns::DnsCommand, token::TokenCommand},
    config, daemon, database, logger, rndc, serializer,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "bindizr", version, about)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the bindizr service
    Start {
        /// Run in the foreground (default is background)
        #[arg(short, long)]
        foreground: bool,
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,
        /// Run in silent mode (no stdout)
        #[arg(short, long)]
        silent: bool,
    },
    /// Stop the bindizr service
    Stop,
    /// Show the status of the bindizr service
    Status,
    /// Manage DNS system
    Dns {
        #[command(subcommand)]
        subcommand: DnsCommand,
    },
    /// Manage API tokens
    Token {
        #[command(subcommand)]
        subcommand: TokenCommand,
    },
}

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
    database::initialize().await;
    rndc::initialize();
    serializer::initialize();

    daemon::socket::server::initialize().await?;
    api::initialize().await?;

    Ok(())
}

pub async fn execute() {
    let args = Args::parse();

    // Execute command
    if let Err(e) = match args.command {
        Command::Start {
            foreground,
            config,
            silent,
        } => start::handle_command(foreground, config, silent).await,
        Command::Stop => stop::handle_command().await,
        Command::Status => status::handle_command().await,
        Command::Dns { subcommand } => dns::handle_command(subcommand).await,
        Command::Token { subcommand } => token::handle_command(subcommand).await,
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
