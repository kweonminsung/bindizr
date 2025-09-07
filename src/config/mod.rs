#[cfg(test)]
mod tests;

use config::{Config, File, FileFormat, Source, ValueKind};
use once_cell::sync::OnceCell;
use std::{any::type_name, collections::HashMap, str::FromStr};

// Config file path
pub const CONF_FILE_PATH: &str = "/etc/bindizr/bindizr.conf.toml";

static CONFIG: OnceCell<Config> = OnceCell::new();

pub fn initialize(conf_file_path: Option<&str>) {
    let conf_file_path = conf_file_path.unwrap_or(CONF_FILE_PATH);

    println!("Initializing configuration from file: {}", conf_file_path);

    let cfg = Config::builder()
        .add_source(File::new(conf_file_path, FileFormat::Toml).required(true))
        .build()
        .expect("Failed to build configuration");

    CONFIG.get_or_init(|| cfg);
}

fn get_config_str(key: &str) -> String {
    CONFIG
        .get()
        .expect("Configuration not initialized")
        .get::<config::Value>(key)
        .expect(&format!("Configuration key '{}' not found", key))
        .into_string()
        .unwrap()
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

pub fn get_config<T: 'static + FromStr>(key: &str) -> T
where
    <T as FromStr>::Err: std::fmt::Display,
{
    let value_str = get_config_str(key);

    value_str.parse::<T>().unwrap_or_else(|e| {
        panic!(
            "Failed to parse configuration for '{}'. Expected type: {}. Error: {}",
            key,
            type_name::<T>(),
            e
        )
    })
}
