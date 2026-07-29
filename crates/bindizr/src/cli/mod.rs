mod commands;
pub(crate) mod error;
mod output;

use std::sync::Arc;

use async_trait::async_trait;
use bindizr_core::{config, log_error, log_info, logger};
use bindizr_db as database;
use bindizr_dns as dns;
use bindizr_service as service;
use clap::{Parser, Subcommand};

use crate::{
    api,
    cli::commands::{
        config::ConfigCommand, record::RecordCommand, token::TokenCommand,
        tsig_key::TsigKeyCommand, zone::ZoneCommand,
    },
    socket,
};

struct DnsNotifySender;

#[async_trait]
impl service::notify::NotifySender for DnsNotifySender {
    async fn send_notify(&self, zone_name: Option<&str>) -> Result<(), String> {
        dns::client::notify::send_notify(zone_name, false)
            .await
            .map_err(|e| e.to_string())
    }
}

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

/// Initialize config, logging, database, DNS, socket, and API servers, then run until Ctrl+C.
pub(crate) async fn bootstrap(config_file: Option<&str>) -> Result<(), String> {
    config::initialize(config_file);

    logger::initialize();
    service::notify::set_notify_sender(Arc::new(DnsNotifySender)).map_err(String::from)?;
    service::notify::init_apply_worker();
    database::initialize().await;
    dns::initialize().await;

    if config::get_bindizr_config().dns.notify_on_startup {
        match dns::client::notify::send_notify(None, false).await {
            Ok(()) => log_info!("Startup DNS NOTIFY completed."),
            Err(e) => log_error!("Startup DNS NOTIFY failed: {}", e),
        }
    }

    log_info!("Bindizr is running in foreground mode.");
    log_info!("For production use, please run bindizr as a systemd service:");
    log_info!("# systemctl start bindizr");

    socket::server::initialize().await?;
    api::initialize().await?;

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("Failed to listen for shutdown signal: {}", e))?;

    log_info!("Shutdown signal received, exiting gracefully...");

    Ok(())
}

/// Parse CLI arguments and dispatch to the matching command handler.
pub async fn execute() {
    let args = Args::parse();

    if let Err(e) = match args.command {
        Command::Start { config } => commands::start::handle_command(config)
            .await
            .map_err(error::CliError::from),
        Command::Status => commands::status::handle_command().await,
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
