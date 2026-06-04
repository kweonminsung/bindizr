#[cfg(test)]
mod tests;

use config::{Config, File, FileFormat};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::{env, fmt, net::IpAddr, path::PathBuf};

// Config file path
pub const BINDIZR_CONF_DIR: &str = "/etc/bindizr";
pub const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

static BINDIZR_CONFIG: OnceCell<BindizrConfig> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BindizrConfig {
    pub listen_addr: IpAddr,
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiConfig {
    #[serde(alias = "port")]
    pub listen_port: u16,
    pub require_authentication: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(rename = "type")]
    pub database_type: DatabaseType,
    #[serde(default)]
    pub mysql: MysqlConfig,
    #[serde(default)]
    pub sqlite: SqliteConfig,
    #[serde(alias = "postgres", default)]
    pub postgresql: PostgresqlConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    Mysql,
    Sqlite,
    Postgresql,
}

impl fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            DatabaseType::Mysql => "mysql",
            DatabaseType::Sqlite => "sqlite",
            DatabaseType::Postgresql => "postgresql",
        };
        write!(f, "{}", value)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MysqlConfig {
    pub server_url: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SqliteConfig {
    pub file_path: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PostgresqlConfig {
    pub server_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsConfig {
    pub listen_port: u16,
    pub secondary_addrs: String,
    #[serde(default = "default_notify_after_update")]
    pub notify_after_update: bool,
    #[serde(default)]
    pub notify_on_startup: bool,
    /// Empty disables nsupdate TSIG authentication.
    #[serde(default)]
    pub nsupdate_tsig_key: String,
}

fn default_notify_after_update() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub log_level: LogLevel,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        write!(f, "{}", value)
    }
}

pub fn initialize(conf_file_path: Option<&str>) {
    let conf_file_path = conf_file_path
        .map(str::to_string)
        .or_else(|| env::var("BINDIZR_CONFIG_PATH").ok())
        .unwrap_or_else(|| BINDIZR_CONF_PATH.to_string());

    if !PathBuf::from(&conf_file_path).exists() {
        exit_config_error(format!("Bindizr config does not exist: {}", conf_file_path));
    }

    println!("Initializing configuration from file: {}", conf_file_path);

    let cfg = load_raw_config(&conf_file_path).unwrap_or_else(|err| exit_config_error(err));
    let bindizr_config = parse_bindizr_config(cfg).unwrap_or_else(|err| exit_config_error(err));

    BINDIZR_CONFIG.get_or_init(|| bindizr_config);
}

fn load_raw_config(conf_file_path: &str) -> Result<Config, String> {
    Config::builder()
        .add_source(File::new(conf_file_path, FileFormat::Toml).required(true))
        .build()
        .map_err(|e| {
            format!(
                "Failed to build configuration from file '{}': {}",
                conf_file_path, e
            )
        })
}

fn parse_bindizr_config(cfg: Config) -> Result<BindizrConfig, String> {
    parse_bindizr_config_with_env(cfg, |name| env::var(name).ok())
}

fn parse_bindizr_config_with_env(
    cfg: Config,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<BindizrConfig, String> {
    let mut bindizr_config = cfg
        .try_deserialize::<BindizrConfig>()
        .map_err(|e| format!("Invalid Bindizr configuration: {}", e))?;

    apply_env_overrides_from(&mut bindizr_config, get_env)?;
    validate_database_config(&bindizr_config.database)?;

    Ok(bindizr_config)
}

fn apply_env_overrides_from(
    config: &mut BindizrConfig,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<(), String> {
    if let Some(value) = get_env("BINDIZR_LISTEN_ADDR") {
        config.listen_addr = parse_env_value("BINDIZR_LISTEN_ADDR", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_API_PORT") {
        config.api.listen_port = parse_env_value("BINDIZR_API_PORT", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_API_REQUIRE_AUTHENTICATION") {
        config.api.require_authentication =
            parse_env_value("BINDIZR_API_REQUIRE_AUTHENTICATION", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_DATABASE_TYPE") {
        config.database.database_type = parse_database_type_env("BINDIZR_DATABASE_TYPE", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_MYSQL_SERVER_URL") {
        config.database.mysql.server_url = value;
    }
    if let Some(value) = get_env("BINDIZR_POSTGRESQL_SERVER_URL") {
        config.database.postgresql.server_url = value;
    }
    if let Some(value) = get_env("BINDIZR_SQLITE_FILE_PATH") {
        config.database.sqlite.file_path = value;
    }
    if let Some(value) = get_env("BINDIZR_DATABASE_URL") {
        match config.database.database_type {
            DatabaseType::Mysql => config.database.mysql.server_url = value,
            DatabaseType::Postgresql => config.database.postgresql.server_url = value,
            DatabaseType::Sqlite => {}
        }
    }
    if let Some(value) = get_env("BINDIZR_DNS_PORT") {
        config.dns.listen_port = parse_env_value("BINDIZR_DNS_PORT", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_SECONDARY_ADDRS") {
        config.dns.secondary_addrs = value;
    }
    if let Some(value) = get_env("BINDIZR_NSUPDATE_TSIG_KEY") {
        config.dns.nsupdate_tsig_key = value;
    } else if let Some(value) = get_env("TSIG_SECRET") {
        config.dns.nsupdate_tsig_key = value;
    }
    if let Some(value) = get_env("BINDIZR_NOTIFY_AFTER_UPDATE") {
        config.dns.notify_after_update = parse_env_value("BINDIZR_NOTIFY_AFTER_UPDATE", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_NOTIFY_ON_STARTUP") {
        config.dns.notify_on_startup = parse_env_value("BINDIZR_NOTIFY_ON_STARTUP", &value)?;
    }
    if let Some(value) = get_env("BINDIZR_LOG_LEVEL") {
        config.logging.log_level = parse_log_level_env("BINDIZR_LOG_LEVEL", &value)?;
    }

    Ok(())
}

fn parse_env_value<T>(name: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|e| format!("Invalid {} environment variable '{}': {}", name, value, e))
}

fn parse_database_type_env(name: &str, value: &str) -> Result<DatabaseType, String> {
    match value {
        "mysql" => Ok(DatabaseType::Mysql),
        "postgresql" => Ok(DatabaseType::Postgresql),
        "sqlite" => Ok(DatabaseType::Sqlite),
        _ => Err(format!(
            "Invalid {} environment variable '{}': expected mysql, postgresql, or sqlite",
            name, value
        )),
    }
}

fn parse_log_level_env(name: &str, value: &str) -> Result<LogLevel, String> {
    match value {
        "trace" => Ok(LogLevel::Trace),
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warn" => Ok(LogLevel::Warn),
        "error" => Ok(LogLevel::Error),
        _ => Err(format!(
            "Invalid {} environment variable '{}': expected trace, debug, info, warn, or error",
            name, value
        )),
    }
}

fn validate_database_config(config: &DatabaseConfig) -> Result<(), String> {
    match config.database_type {
        DatabaseType::Mysql if config.mysql.server_url.trim().is_empty() => Err(
            "database.mysql.server_url must not be empty when database.type is mysql".to_string(),
        ),
        DatabaseType::Postgresql if config.postgresql.server_url.trim().is_empty() => Err(
            "database.postgresql.server_url must not be empty when database.type is postgresql"
                .to_string(),
        ),
        DatabaseType::Sqlite if config.sqlite.file_path.trim().is_empty() => Err(
            "database.sqlite.file_path must not be empty when database.type is sqlite".to_string(),
        ),
        _ => Ok(()),
    }
}

fn exit_config_error(message: String) -> ! {
    eprintln!("{}", message);
    std::process::exit(1);
}

pub fn get_bindizr_config() -> &'static BindizrConfig {
    BINDIZR_CONFIG.get().expect("Configuration not initialized")
}
