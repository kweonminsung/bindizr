//! Command-line grammar and dispatch. Every subcommand either talks to the
//! running daemon over its Unix socket or starts one; the daemon runtime
//! itself lives in [`crate::daemon`].

mod commands;
pub(crate) mod error;
mod output;

use clap::{Parser, Subcommand};

use crate::cli::commands::{
    config::ConfigCommand, record::RecordCommand, token::TokenCommand, tsig_key::TsigKeyCommand,
    zone::ZoneCommand,
};

/// Top-level CLI argument parser.
#[derive(Parser, Debug)]
#[command(name = "bindizr", version, about)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level CLI subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Start bindizr on foreground
    Start {
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,
    },
    /// Show the status of the bindizr service
    Status,
    /// Stop the running bindizr daemon
    Stop,
    /// Restart the running bindizr daemon in place
    Restart,
    /// Check that the bindizr installation is healthy
    Doctor {
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,
    },
    /// Inspect and validate configuration
    Config {
        #[command(subcommand)]
        subcommand: ConfigCommand,
    },
    /// Manage API tokens
    Token {
        #[command(subcommand)]
        subcommand: TokenCommand,
    },
    /// Manage TSIG keys for nsupdate authentication
    TsigKey {
        #[command(subcommand)]
        subcommand: TsigKeyCommand,
    },
    /// Manage zones
    Zone {
        #[command(subcommand)]
        subcommand: ZoneCommand,
    },
    /// Manage records
    Record {
        #[command(subcommand)]
        subcommand: RecordCommand,
    },
}

/// Parse CLI arguments and dispatch to the matching command handler.
pub async fn execute() {
    let args = Args::parse();

    if let Err(e) = match args.command {
        Command::Start { config } => commands::start::handle_command(config)
            .await
            .map_err(error::CliError::from),
        Command::Status => commands::status::handle_command().await,
        Command::Stop => commands::stop::handle_command().await,
        Command::Restart => commands::restart::handle_command().await,
        Command::Doctor { config } => commands::doctor::handle_command(config).await,
        Command::Config { subcommand } => commands::config::handle_command(subcommand).await,
        Command::Token { subcommand } => commands::token::handle_command(subcommand).await,
        Command::TsigKey { subcommand } => commands::tsig_key::handle_command(subcommand).await,
        Command::Zone { subcommand } => commands::zone::handle_command(subcommand).await,
        Command::Record { subcommand } => commands::record::handle_command(subcommand).await,
    } {
        eprintln!("Error: {}", e.message);
        if let Some(hint) = e.hint() {
            eprintln!("Hint: {}", hint);
        }
        std::process::exit(1);
    }
}
