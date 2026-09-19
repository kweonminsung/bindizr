//! Command-line grammar and dispatch. Every subcommand either talks to the
//! running daemon over its Unix socket or starts one; the daemon runtime
//! itself lives in [`crate::daemon`].

mod commands;
pub(crate) mod error;
mod output;

use bindizr_core::errln;
use clap::{Parser, Subcommand};
use clap_complete::Shell;

use crate::{
    cli::{
        commands::{
            config::ConfigCommand, dnssec::DnssecCommand, dnssec_policy::DnssecPolicyCommand,
            record::RecordCommand, token::TokenCommand, tsig_key::TsigKeyCommand,
            zone::ZoneCommand,
        },
        output::OutputFormat,
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
    Stop {
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Restart the running bindizr daemon in place
    Restart {
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show the status of the bindizr service
    Status {
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Check that the bindizr installation is healthy
    Doctor {
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
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
    /// Manage TSIG keys and their zone update and transfer rights
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
    /// Print a shell completion script on stdout
    #[command(after_help = "\
Examples:
  bindizr completion bash | sudo tee /usr/share/bash-completion/completions/bindizr
  bindizr completion zsh  | sudo tee /usr/share/zsh/site-functions/_bindizr
  bindizr completion fish > ~/.config/fish/completions/bindizr.fish")]
    Completion {
        /// Shell to generate for
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Print the bindizr man page (roff) on stdout
    #[command(after_help = "\
Example:
  bindizr man | sudo tee /usr/share/man/man1/bindizr.1 > /dev/null")]
    Man,
}

/// Parse CLI arguments and dispatch to the matching command handler.
pub async fn execute() {
    let args = Args::parse();

    let result = match args.command {
        Command::Start { config } => daemon::bootstrap(config.as_deref()).await,
        Command::Stop { output } => commands::stop::handle_command(output).await,
        Command::Restart { output } => commands::restart::handle_command(output).await,
        Command::Status { output } => commands::status::handle_command(output).await,
        Command::Doctor { config, output } => {
            commands::doctor::handle_command(config, output).await
        }
        Command::Config { subcommand } => commands::config::handle_command(subcommand).await,
        Command::Zone { subcommand } => commands::zone::handle_command(subcommand).await,
        Command::Record { subcommand } => commands::record::handle_command(subcommand).await,
        Command::Token { subcommand } => commands::token::handle_command(subcommand).await,
        Command::TsigKey { subcommand } => commands::tsig_key::handle_command(subcommand).await,
        Command::DnssecPolicy { subcommand } => {
            commands::dnssec_policy::handle_command(subcommand).await
        }
        Command::Dnssec { subcommand } => commands::dnssec::handle_command(subcommand).await,
        Command::Completion { shell } => commands::completion::handle_command(shell),
        Command::Man => commands::completion::handle_man_command(),
    };

    // Lost output must not read as success; a reader that stopped early is
    // not lost output.
    let result = result.and_then(|()| match bindizr_core::stream::write_failure() {
        Some(failure) => Err(error::CliError::from(format!(
            "output was lost: {}",
            failure
        ))),
        None => Ok(()),
    });

    if let Err(e) = result {
        errln!("Error: {}", e.message);
        if let Some(hint) = e.hint() {
            errln!("Hint: {}", hint);
        }
        std::process::exit(e.exit_code());
    }
}
