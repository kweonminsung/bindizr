use bindizr_core::{config, config::BindizrConfig};
use clap::Subcommand;

use crate::{
    cli::{error::CliError, output::color},
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
    },
    /// Show the configuration loaded by the running daemon
    #[command(alias = "ls")]
    List,
    /// Re-read the configuration file in the running daemon
    #[command(after_help = "\
Settings bound to something built at startup — the `api` section, the
`database` section, and the DNS listen address and port — are fixed while
bindizr runs. A file that changes one of them is refused whole, so the
running configuration always describes the running process.")]
    Reload,
    /// Show a single configuration value by dotted key (e.g. api.listen_port)
    Get {
        /// Dotted configuration key, e.g. dns.secondary_addrs
        key: String,
    },
}

/// Handle the `config` subcommand.
pub(crate) async fn handle_command(subcommand: ConfigCommand) -> Result<(), CliError> {
    match subcommand {
        ConfigCommand::Check { config } => validate_config(config.as_deref()),
        ConfigCommand::List => print_config_list().await,
        ConfigCommand::Reload => reload_config().await,
        ConfigCommand::Get { key } => print_config_value(&key).await,
    }
}

/// Ask the daemon to reload its configuration.
async fn reload_config() -> Result<(), CliError> {
    let response = client::send_command(DaemonCommandKind::ReloadConfig, ()).await?;
    println!("{}", response.message);
    Ok(())
}

/// Validate the local configuration file.
fn validate_config(file: Option<&str>) -> Result<(), CliError> {
    let path = config::resolve_config_path(file);
    println!("Checking configuration file: {}", path);

    config::load_config_file(&path)?;

    println!("Configuration is {}.", color::green("valid"));
    Ok(())
}

/// Print all effective configuration values.
async fn print_config_list() -> Result<(), CliError> {
    let config = client::fetch_config().await?;
    print_config(&config);
    Ok(())
}

/// Print one effective configuration value by key.
async fn print_config_value(key: &str) -> Result<(), CliError> {
    let config = client::fetch_config().await?;
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

/// Print configuration values grouped by section.
fn print_config(config: &BindizrConfig) {
    print_section("api");
    print_value("listen_addr", config.api.listen_addr);
    print_value("listen_port", config.api.listen_port);
    print_value("metrics_enabled", config.api.metrics_enabled);
    print_value("external_dns_enabled", config.api.external_dns_enabled);
    print_value("openapi_enabled", config.api.openapi_enabled);
    print_optional("tls_cert_file", config.api.tls_cert_file.as_deref());
    print_optional("tls_key_file", config.api.tls_key_file.as_deref());
    println!();

    print_section("api.authentication");
    print_value("required", config.api.authentication.required);
    print_optional(
        "initial_token",
        config.api.authentication.initial_token.as_deref(),
    );
    println!();

    print_section("database");
    print_value("type", config.database.database_type);
    println!();

    print_section("database.mysql");
    print_value("url", &config.database.mysql.url);
    println!();

    print_section("database.sqlite");
    print_value("file_path", &config.database.sqlite.file_path);
    println!();

    print_section("database.postgresql");
    print_value("url", &config.database.postgresql.url);
    println!();

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
    println!();

    print_section("dns.nsupdate");
    print_value("tsig_required", config.dns.nsupdate.tsig_required);
    if let Some(key) = &config.dns.nsupdate.initial_key {
        print_value("initial_key.name", &key.name);
        print_value("initial_key.secret", &key.secret);
        print_optional("initial_key.algorithm", key.algorithm.as_deref());
    }
    println!();

    print_section("dns.notify");
    print_value("after_update", config.dns.notify.after_update);
    print_value("on_startup", config.dns.notify.on_startup);
    print_value("batch_ms", config.dns.notify.batch_ms);
    print_value("retries", config.dns.notify.retries);
    print_value("timeout_secs", config.dns.notify.timeout_secs);
    println!();

    print_section("dns.transfer_cache");
    print_value("enabled", config.dns.transfer_cache.enabled);
    print_value("max_records", config.dns.transfer_cache.max_records);
    println!();

    print_section("dns.zone_defaults");
    print_value("ttl", config.dns.zone_defaults.ttl);
    print_value("refresh", config.dns.zone_defaults.refresh);
    print_value("retry", config.dns.zone_defaults.retry);
    print_value("expire", config.dns.zone_defaults.expire);
    print_value("minimum_ttl", config.dns.zone_defaults.minimum_ttl);
    println!();

    print_section("logging");
    print_value("level", config.logging.level);
    print_value("format", config.logging.format);
}

/// Print a configuration section heading.
fn print_section(name: &str) {
    println!("{}", color::cyan(&format!("[{}]", name)));
}

/// A value the configuration may leave out, shown as unset rather than absent
/// so the list says what the daemon actually holds.
fn print_optional(key: &str, value: Option<&str>) {
    print_value(key, value.unwrap_or("(unset)"));
}

/// Print one configuration key and its value.
fn print_value(key: &str, value: impl std::fmt::Display) {
    println!("  {} = {}", color::yellow(&format!("{:<24}", key)), value);
}
