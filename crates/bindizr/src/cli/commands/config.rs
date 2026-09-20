use bindizr_core::{config, config::BindizrConfig, outln};
use bindizr_service::types::MessageResponse;
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, color, parse_response, print_payload},
    },
    socket::{client, types::DaemonCommandKind},
};

/// Subcommands for inspecting and validating configuration.
#[derive(Subcommand, Debug)]
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
`database` section, and the DNS listen address and port — are fixed while
bindizr runs. A file that changes one of them is refused whole, so the
running configuration always describes the running process.")]
    Reload {
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
    /// Show a single configuration value by dotted key (e.g. api.listen_port)
    Get {
        /// Dotted configuration key, e.g. dns.secondary_addrs
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
    let response = client::send_command(DaemonCommandKind::ReloadConfig, ()).await?;
    match output {
        OutputFormat::Table => outln!("{}", response.message),
        _ => print_payload(&response.data, output)?,
    }
    Ok(())
}

/// Validate the local configuration file.
fn validate_config(file: Option<&str>, output: OutputFormat) -> Result<(), CliError> {
    let path = config::resolve_config_path(file);
    if output == OutputFormat::Table {
        outln!("Checking configuration file: {}", path);
    }

    config::load_config_file(&path).map_err(CliError::configuration)?;

    let message = format!("Configuration file '{}' is valid", path);
    match output {
        OutputFormat::Table => outln!("Configuration is {}.", color::green("valid")),
        // Built here rather than by the daemon: the check never reaches one.
        _ => {
            let payload = serde_json::to_value(MessageResponse { message })
                .map_err(|e| CliError::from(e.to_string()))?;
            print_payload(&payload, output)?
        }
    }
    Ok(())
}

/// Print all effective configuration values.
async fn print_config_list(output: OutputFormat) -> Result<(), CliError> {
    let response = client::send_control_command(DaemonCommandKind::Config).await?;

    match output {
        OutputFormat::Table => print_config(&parse_response(&response.data)?),
        _ => print_payload(&response.data, output)?,
    }
    Ok(())
}

/// Print one effective configuration value by key. The plain form prints a
/// string bare, so a value can be read straight into a shell variable.
async fn print_config_value(key: &str, output: OutputFormat) -> Result<(), CliError> {
    let response = client::send_control_command(DaemonCommandKind::Config).await?;

    let found = key
        .split('.')
        .try_fold(&response.data, |value, part| value.get(part))
        .ok_or_else(|| format!("Unknown configuration key: {}", key))?;

    match output {
        OutputFormat::Table => match found {
            serde_json::Value::String(value) => outln!("{}", value),
            serde_json::Value::Object(_) => outln!(
                "{}",
                serde_json::to_string_pretty(found)
                    .map_err(|e| format!("Failed to render configuration value: {}", e))?
            ),
            value => outln!("{}", value),
        },
        _ => print_payload(found, output)?,
    }
    Ok(())
}

/// Print configuration values grouped by section.
fn print_config(config: &BindizrConfig) {
    print_section("api");
    print_value("listen_addr", config.api.listen_addr);
    print_value("listen_port", config.api.listen_port);
    print_value(
        "authentication_required",
        config.api.authentication_required,
    );
    print_value("metrics_enabled", config.api.metrics_enabled);
    print_value("external_dns_enabled", config.api.external_dns_enabled);
    print_value("openapi_enabled", config.api.openapi_enabled);
    print_optional("tls_cert_file", config.api.tls_cert_file.as_deref());
    print_optional("tls_key_file", config.api.tls_key_file.as_deref());
    outln!();

    print_section("database");
    print_value("type", config.database.database_type);
    outln!();

    print_section("database.mysql");
    print_value("url", &config.database.mysql.url);
    outln!();

    print_section("database.sqlite");
    print_value("file_path", &config.database.sqlite.file_path);
    outln!();

    print_section("database.postgresql");
    print_value("url", &config.database.postgresql.url);
    outln!();

    print_section("dns");
    print_value("listen_addr", config.dns.listen_addr);
    print_value("listen_port", config.dns.listen_port);
    print_value("secondary_addrs", &config.dns.secondary_addrs);
    print_value(
        "zone_history_retention_days",
        config.dns.zone_history_retention_days,
    );
    print_value(
        "scheduler_interval_secs",
        config.dns.scheduler_interval_secs,
    );
    print_value("nsupdate_tsig_required", config.dns.nsupdate_tsig_required);
    outln!();

    print_section("dns.notify");
    print_value("after_update", config.dns.notify.after_update);
    print_value("on_startup", config.dns.notify.on_startup);
    print_value("batch_ms", config.dns.notify.batch_ms);
    print_value("retries", config.dns.notify.retries);
    print_value("timeout_secs", config.dns.notify.timeout_secs);
    outln!();

    print_section("dns.transfer_cache");
    print_value("enabled", config.dns.transfer_cache.enabled);
    print_value("max_records", config.dns.transfer_cache.max_records);
    outln!();

    print_section("dns.zone_defaults");
    print_value("ttl", config.dns.zone_defaults.ttl);
    print_value("refresh", config.dns.zone_defaults.refresh);
    print_value("retry", config.dns.zone_defaults.retry);
    print_value("expire", config.dns.zone_defaults.expire);
    print_value("minimum_ttl", config.dns.zone_defaults.minimum_ttl);
    outln!();

    print_section("logging");
    print_value("level", config.logging.level);
    print_value("format", config.logging.format);
}

/// Print a configuration section heading.
fn print_section(name: &str) {
    outln!("{}", color::cyan(&format!("[{}]", name)));
}

/// A value the configuration may leave out, shown as unset rather than absent
/// so the list says what the daemon actually holds.
fn print_optional(key: &str, value: Option<&str>) {
    print_value(key, value.unwrap_or("(unset)"));
}

/// Print one configuration key and its value.
fn print_value(key: &str, value: impl std::fmt::Display) {
    outln!("  {} = {}", color::yellow(&format!("{:<24}", key)), value);
}
