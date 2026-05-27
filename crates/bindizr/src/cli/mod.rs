mod commands;
mod output;

use crate::{
    api,
    cli::commands::{notify::NotifyCommand, token::TokenCommand},
    config, database, dns, log_info, logger, service, socket,
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
    /// Start bindizr on foreground
    Start {
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,
    },
    /// Show the status of the bindizr service
    Status,
    /// Manage API tokens
    Token {
        #[command(subcommand)]
        subcommand: TokenCommand,
    },
    /// Get resources
    Get {
        #[command(subcommand)]
        subcommand: commands::get::GetCommand,
    },
    /// Create resources
    Create {
        #[command(subcommand)]
        subcommand: commands::create::CreateCommand,
    },
    /// Delete resources
    Delete {
        #[command(subcommand)]
        subcommand: commands::delete::DeleteCommand,
    },
    /// Send NOTIFY to secondary servers
    Notify {
        #[command(subcommand)]
        subcommand: NotifyCommand,
    },
}

pub async fn bootstrap(config_file: Option<&str>) -> Result<(), String> {
    // Initialize Configuration
    if let Some(file) = config_file {
        // Load configuration from the specified file
        config::initialize(Some(file));
    } else {
        // Use default configuration file
        config::initialize(None);
    }

    logger::initialize();
    service::notify::set_notify_hook(|zone_name| {
        Box::pin(async move {
            dns::xfr::notify::send_notify(zone_name.as_deref())
                .await
                .map_err(|e| e.to_string())
        })
    });
    database::initialize().await;
    dns::initialize().await;

    log_info!("Bindizr is running in foreground mode.");
    log_info!("For production use, please run bindizr as a systemd service:");
    log_info!("# systemctl start bindizr");

    socket::server::initialize().await?;
    api::initialize().await?;

    // Wait only for Ctrl+C signal, ignore all stdin input
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("Failed to listen for shutdown signal: {}", e))?;

    log_info!("Shutdown signal received, exiting gracefully...");

    Ok(())
}

pub async fn execute() {
    let args = Args::parse();

    // Execute command
    if let Err(e) = match args.command {
        Command::Start { config } => commands::start::handle_command(config).await,
        Command::Status => commands::status::handle_command().await,
        Command::Token { subcommand } => commands::token::handle_command(subcommand).await,
        Command::Get { subcommand } => commands::get::handle_command(subcommand).await,
        Command::Create { subcommand } => commands::create::handle_command(subcommand).await,
        Command::Delete { subcommand } => commands::delete::handle_command(subcommand).await,
        Command::Notify { subcommand } => commands::notify::handle_notify(&subcommand).await,
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
