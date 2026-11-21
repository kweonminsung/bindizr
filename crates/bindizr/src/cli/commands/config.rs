use std::fmt;

use bindizr_core::config::Config;
use bindizr_core::{config, outln};
use bindizr_service::types::MessageResponse;
use clap::Subcommand;
use serde_json::Value;

use crate::cli::error::CliError;
use crate::cli::output;
use crate::cli::output::{OutputFormat, RenderOutputError, color};
use crate::socket::client;
use crate::socket::types::DaemonCommand;

/// Subcommands for inspecting and validating configuration.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub(crate) enum ConfigCommand {
    /// Validate a configuration file without starting bindizr
    Check {
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        #[arg(short, long, value_name = "FILE")]
        config: Option<String>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show the configuration loaded by the running daemon
    #[command(alias = "ls")]
    List {
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Re-read the configuration file in the running daemon
    #[command(after_help = "\
Settings bound to something built at startup — the `api` section, the
`database` section, the DNS listen address and port, `dns.tls`,
`dns.tcp_max_connections`, and `dns.catalog_zone_name` — are fixed while
bindizr runs. A file that changes one of them is refused whole, so the
running configuration always describes the running process.")]
    Reload {
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show a single configuration value by dotted key (e.g. api.listen_port)
    Get {
        /// Dotted configuration key, e.g. dns.listen_port
        key: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// Handle the `config` subcommand.
pub(crate) async fn handle_command(subcommand: ConfigCommand) -> Result<(), CliError> {
    match subcommand {
        ConfigCommand::Check { config, output } => validate_config(config.as_deref(), output),
        ConfigCommand::List { output } => print_config_list(output).await,
        ConfigCommand::Reload { output } => reload_config(output).await,
        ConfigCommand::Get { key, output } => print_config_value(&key, output).await,
    }
}

/// Ask the daemon to reload its configuration.
async fn reload_config(output: OutputFormat) -> Result<(), CliError> {
    let response = client::send_command::<MessageResponse>(DaemonCommand::ReloadConfig).await?;

    if output == OutputFormat::Table {
        outln!("{}", response.message);
    } else {
        output::print_payload(&response.data, output)?;
    }

    Ok(())
}

/// Validate the local configuration file.
fn validate_config(config_file: Option<&str>, output: OutputFormat) -> Result<(), CliError> {
    let path = config::resolve_config_path(config_file);

    if output == OutputFormat::Table {
        outln!("Checking configuration file: {path}");
    }

    Config::load(&path)?;

    let message = format!("Configuration file '{path}' is valid");

    if output == OutputFormat::Table {
        outln!("Configuration is {}.", color::green("valid"));
    } else {
        // Built here rather than by the daemon: the check never reaches one.
        output::print_payload(&MessageResponse { message }, output)?;
    }

    Ok(())
}

/// Print all effective configuration values.
async fn print_config_list(output: OutputFormat) -> Result<(), CliError> {
    let response = client::send_control_command::<Config>(DaemonCommand::Config).await?;

    if output == OutputFormat::Table {
        let config = serde_json::to_value(&response.data).map_err(RenderOutputError::Json)?;
        print_config(&config, "");
    } else {
        output::print_payload(&response.data, output)?;
    }

    Ok(())
}

/// Print one effective configuration value by key. The plain form prints a
/// string bare, so a value can be read straight into a shell variable.
async fn print_config_value(key: &str, output: OutputFormat) -> Result<(), CliError> {
    let response = client::send_control_command::<Config>(DaemonCommand::Config).await?;
    let config = serde_json::to_value(&response.data).map_err(RenderOutputError::Json)?;

    let found = key
        .split('.')
        .try_fold(&config, |value, part| value.get(part))
        .ok_or_else(|| CliError::request(format!("unknown configuration key: {key}")))?;

    if output == OutputFormat::Table {
        match found {
            Value::String(value) => outln!("{value}"),
            Value::Object(_) => outln!(
                "{}",
                serde_json::to_string_pretty(found).map_err(|error| {
                    CliError::request_with_source(
                        format!("failed to render configuration value: {error}"),
                        error,
                    )
                })?
            ),
            value => outln!("{value}"),
        }
    } else {
        output::print_payload(found, output)?;
    }

    Ok(())
}

/// Print the serialized configuration grouped by section, `config get`'s
/// view of it: an object is a `[section]`, every other value a key under it.
fn print_config(value: &Value, section: &str) {
    let Value::Object(fields) = value else {
        return;
    };
    let (sections, keys): (Vec<_>, Vec<_>) =
        fields.iter().partition(|(_, value)| value.is_object());

    if !keys.is_empty() {
        print_section(section);

        for (key, value) in keys {
            match value {
                // Shown as unset rather than absent, so the list says what the daemon holds.
                Value::Null => print_value(key, "(unset)"),
                Value::String(value) => print_value(key, value),
                value => print_value(key, value),
            }
        }

        outln!();
    }

    for (key, value) in sections {
        let path = if section.is_empty() {
            key.clone()
        } else {
            format!("{section}.{key}")
        };
        print_config(value, &path);
    }
}

/// Print a configuration section heading.
fn print_section(name: &str) {
    outln!("{}", color::cyan(&format!("[{name}]")));
}

/// Print one configuration key and its value.
fn print_value(key: &str, value: impl fmt::Display) {
    outln!("  {} = {value}", color::yellow(&format!("{key:<24}")));
}
