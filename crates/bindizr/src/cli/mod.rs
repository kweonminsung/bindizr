//! Command-line grammar and dispatch. Every subcommand either talks to the
//! running daemon over its Unix socket or starts one; the daemon runtime
//! itself lives in [`crate::daemon`].

mod commands;
pub(crate) mod error;
mod output;

use clap::{Parser, Subcommand};

use crate::{
    cli::commands::{
        config::ConfigCommand, dnssec::DnssecCommand, dnssec_policy::DnssecPolicyCommand,
        record::RecordCommand, token::TokenCommand, tsig_key::TsigKeyCommand, zone::ZoneCommand,
    },
    daemon,
};

/// Top-level CLI argument parser.
#[derive(Parser, Debug)]
#[command(name = "bindizr", version, about)]
pub(crate) struct Args {
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Top-level CLI subcommands. Declaration order is `--help` order, and it
/// keeps `dnssec-policy` beside the `dnssec` commands that sign under it.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Start bindizr on foreground
    Start {
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,
    },
    /// Stop the running bindizr daemon
    Stop,
    /// Restart the running bindizr daemon in place
    Restart,
    /// Show the status of the bindizr service
    Status,
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
    /// Manage API tokens and the zones each may change over HTTP
    Token {
        #[command(subcommand)]
        subcommand: TokenCommand,
    },
    /// Manage TSIG keys and the zones each may update with nsupdate
    TsigKey {
        #[command(subcommand)]
        subcommand: TsigKeyCommand,
    },
    /// Manage DNSSEC policies, the signing-parameter bundles zones sign under
    DnssecPolicy {
        #[command(subcommand)]
        subcommand: DnssecPolicyCommand,
    },
    /// Manage a zone's DNSSEC signing (keys, DS records, re-signing)
    Dnssec {
        #[command(subcommand)]
        subcommand: DnssecCommand,
    },
}

/// Parse CLI arguments and dispatch to the matching command handler.
pub async fn execute() {
    let args = Args::parse();

    if let Err(e) = match args.command {
        Command::Start { config } => daemon::bootstrap(config.as_deref())
            .await
            .map_err(error::CliError::from),
        Command::Stop => commands::stop::handle_command().await,
        Command::Restart => commands::restart::handle_command().await,
        Command::Status => commands::status::handle_command().await,
        Command::Doctor { config } => commands::doctor::handle_command(config).await,
        Command::Config { subcommand } => commands::config::handle_command(subcommand).await,
        Command::Zone { subcommand } => commands::zone::handle_command(subcommand).await,
        Command::Record { subcommand } => commands::record::handle_command(subcommand).await,
        Command::Token { subcommand } => commands::token::handle_command(subcommand).await,
        Command::TsigKey { subcommand } => commands::tsig_key::handle_command(subcommand).await,
        Command::DnssecPolicy { subcommand } => {
            commands::dnssec_policy::handle_command(subcommand).await
        }
        Command::Dnssec { subcommand } => commands::dnssec::handle_command(subcommand).await,
    } {
        eprintln!("Error: {}", e.message);
        if let Some(hint) = e.hint() {
            eprintln!("Hint: {}", hint);
        }
        std::process::exit(1);
    }
}
