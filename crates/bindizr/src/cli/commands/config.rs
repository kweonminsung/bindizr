use bindizr_core::{config, config::BindizrConfig};
use clap::Subcommand;

use crate::{cli::error::CliError, socket::client::DaemonSocketClient};

/// Subcommands for inspecting and validating configuration.
#[derive(Subcommand, Debug)]
pub(crate) enum ConfigCommand {
    /// Validate a configuration file without starting bindizr
    Check {
        /// Path to the configuration file (default: /etc/bindizr/bindizr.conf.toml)
        file: Option<String>,
    },
    /// Show the configuration loaded by the running daemon
    List,
    /// Show a single configuration value by dotted key (e.g. api.listen_port)
    Get {
        /// Dotted configuration key, e.g. dns.secondary_addrs
        key: String,
    },
}

/// Handle the `config` subcommand.
pub(crate) async fn handle_command(subcommand: ConfigCommand) -> Result<(), CliError> {
    match subcommand {
        ConfigCommand::Check { file } => check_config(file.as_deref()),
        ConfigCommand::List => list_config().await,
        ConfigCommand::Get { key } => get_config(&key).await,
    }
}

fn check_config(file: Option<&str>) -> Result<(), CliError> {
    let path = config::resolve_config_path(file);
    println!("Checking configuration file: {}", path);

    config::load_config_file(&path)?;

    println!("Configuration is \x1b[32mvalid\x1b[0m.");
    Ok(())
}

async fn list_config() -> Result<(), CliError> {
    let config = loaded_daemon_config().await?;
    print_config(&config);
    Ok(())
}

async fn get_config(key: &str) -> Result<(), CliError> {
    let config = loaded_daemon_config().await?;
    let value = serde_json::to_value(&config)
        .map_err(|e| format!("Failed to serialize configuration: {}", e))?;

    let found = key
        .split('.')
        .try_fold(&value, |value, part| value.get(part))
        .ok_or_else(|| format!("Unknown configuration key: {}", key))?;

    match found {
        serde_json::Value::String(value) => println!("{}", value),
        serde_json::Value::Object(_) => println!(
            "{}",
            serde_json::to_string_pretty(found)
                .map_err(|e| format!("Failed to render configuration value: {}", e))?
        ),
        value => println!("{}", value),
    }
    Ok(())
}

/// Fetch the running daemon's loaded config (file plus environment overrides),
/// which can differ from what the file on disk currently says.
async fn loaded_daemon_config() -> Result<BindizrConfig, CliError> {
    Ok(DaemonSocketClient::new().status().await?.config)
}

fn print_config(config: &BindizrConfig) {
    print_section("api");
    print_value("listen_addr", config.api.listen_addr);
    print_value("listen_port", config.api.listen_port);
    print_value("require_authentication", config.api.require_authentication);
    print_value("metrics_enabled", config.api.metrics_enabled);
    print_value("external_dns_enabled", config.api.external_dns_enabled);
    print_value("openapi_enabled", config.api.openapi_enabled);
    println!();

    print_section("database");
    print_value("type", config.database.database_type);
    println!();

    print_section("database.mysql");
    print_value("server_url", &config.database.mysql.server_url);
    println!();

    print_section("database.sqlite");
    print_value("file_path", &config.database.sqlite.file_path);
    println!();

    print_section("database.postgresql");
    print_value("server_url", &config.database.postgresql.server_url);
    println!();

    print_section("dns");
    print_value("listen_addr", config.dns.listen_addr);
    print_value("listen_port", config.dns.listen_port);
    print_value("secondary_addrs", &config.dns.secondary_addrs);
    print_value("notify_after_update", config.dns.notify_after_update);
    print_value("apply_mode", config.dns.apply_mode);
    print_value("apply_batch_ms", config.dns.apply_batch_ms);
    print_value("zone_cache", config.dns.zone_cache);
    print_value("notify_on_startup", config.dns.notify_on_startup);
    print_value("notify_retries", config.dns.notify_retries);
    print_value("notify_timeout_secs", config.dns.notify_timeout_secs);
    print_value(
        "nsupdate_allow_unsigned",
        config.dns.nsupdate_allow_unsigned,
    );
    println!();

    print_section("logging");
    print_value("log_level", config.logging.log_level);
}

fn print_section(name: &str) {
    println!("\x1b[36m[{}]\x1b[0m", name);
}

fn print_value(key: &str, value: impl std::fmt::Display) {
    println!("  \x1b[33m{:<24}\x1b[0m = {}", key, value);
}
