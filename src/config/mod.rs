#[cfg(test)]
mod tests;

pub mod error;

use config::{Config, File, FileFormat, Source, ValueKind};
use once_cell::sync::OnceCell;
use serde::Deserialize;
use std::{collections::HashMap, net::IpAddr, path::PathBuf};

// Config file path
#[allow(dead_code)]
pub const BINDIZR_CONF_DIR: &str = "/etc/bindizr";
pub const BINDIZR_CONF_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

static CONFIG: OnceCell<Config> = OnceCell::new();
static BINDIZR_CONFIG: OnceCell<BindizrConfig> = OnceCell::new();

#[derive(Debug, Deserialize)]
pub struct BindizrConfig {
    pub listen_addr: IpAddr,
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    #[serde(alias = "port")]
    pub listen_port: u16,
    pub require_authentication: bool,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    #[serde(rename = "type")]
    pub database_type: DatabaseType,
    pub mysql: MysqlConfig,
    pub sqlite: SqliteConfig,
    #[serde(alias = "postgres")]
    pub postgresql: PostgresqlConfig,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    Mysql,
    Sqlite,
    Postgresql,
}

#[derive(Debug, Deserialize)]
pub struct MysqlConfig {
    pub server_url: String,
}

#[derive(Debug, Deserialize)]
pub struct SqliteConfig {
    pub file_path: String,
}

#[derive(Debug, Deserialize)]
pub struct PostgresqlConfig {
    pub server_url: String,
}

#[derive(Debug, Deserialize)]
pub struct DnsConfig {
    pub listen_port: u16,
    pub secondary_addrs: String,
    /// Empty disables nsupdate TSIG authentication.
    #[serde(default)]
    pub nsupdate_tsig_key: String,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub log_level: LogLevel,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub fn initialize(conf_file_path: Option<&str>) {
    let conf_file_path = conf_file_path.unwrap_or(BINDIZR_CONF_PATH);

    if !PathBuf::from(conf_file_path).exists() {
        exit_config_error(format!("Bindizr config does not exist: {}", conf_file_path));
    }

    println!("Initializing configuration from file: {}", conf_file_path);

    let cfg = load_raw_config(conf_file_path).unwrap_or_else(|err| exit_config_error(err));
    let bindizr_config = parse_bindizr_config(&cfg).unwrap_or_else(|err| exit_config_error(err));

    CONFIG.get_or_init(|| cfg);
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

fn parse_bindizr_config(cfg: &Config) -> Result<BindizrConfig, String> {
    let bindizr_config = cfg
        .clone()
        .try_deserialize::<BindizrConfig>()
        .map_err(|e| format!("Invalid Bindizr configuration: {}", e))?;

    validate_database_config(&bindizr_config.database)?;

    Ok(bindizr_config)
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

#[allow(dead_code)]
pub fn get_bindizr_config() -> &'static BindizrConfig {
    BINDIZR_CONFIG.get().expect("Configuration not initialized")
}

fn get_config_map() -> Result<HashMap<String, config::Value>, String> {
    CONFIG
        .get()
        .ok_or_else(|| "Configuration not initialized".to_string())?
        .collect()
        .map_err(|e| format!("Failed to collect configuration: {}", e))
}

fn config_value_to_json(val: &config::Value) -> Result<serde_json::Value, String> {
    match &val.kind {
        ValueKind::Nil => Ok(serde_json::Value::Null),
        ValueKind::Boolean(b) => Ok(serde_json::Value::Bool(*b)),
        ValueKind::I64(i) => Ok((*i).into()),
        ValueKind::U64(i) => Ok((*i).into()),
        ValueKind::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .ok_or_else(|| "Invalid float value".to_string()),
        ValueKind::String(s) => Ok(serde_json::Value::String(s.clone())),
        ValueKind::Array(arr) => arr
            .iter()
            .map(config_value_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        ValueKind::Table(map) => map
            .iter()
            .map(|(k, v)| config_value_to_json(v).map(|json| (k.clone(), json)))
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(serde_json::Value::Object),
        _ => Err(format!("Unsupported config value type: {:?}", val.kind)),
    }
}

pub fn get_config_json_map() -> Result<serde_json::Value, String> {
    let raw_map = get_config_map()?;

    let obj = raw_map
        .iter()
        .map(|(k, v)| config_value_to_json(v).map(|json| (k.clone(), json)))
        .collect::<Result<_, _>>()?;

    Ok(serde_json::Value::Object(obj))
}
