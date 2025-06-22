use config::{Config, File, FileFormat, Source, ValueKind};
use once_cell::sync::OnceCell;
use std::{any::type_name, collections::HashMap, str::FromStr};

// Config file path
pub const CONF_FILE_PATH: &str = "/etc/bindizr/bindizr.conf";

static CONFIG: OnceCell<Config> = OnceCell::new();

pub fn initialize() {
    initialize_from_file(CONF_FILE_PATH);
}

pub fn initialize_from_file(conf_file_path: &str) {
    println!("Initializing configuration from file: {}", conf_file_path);

    let cfg = Config::builder()
        .add_source(File::new(conf_file_path, FileFormat::Ini).required(true))
        .build()
        .expect("Failed to build configuration");

    CONFIG
        .set(cfg)
        .expect("Configuration has already been initialized");
}

fn get_config_str(key: &str) -> String {
    CONFIG
        .get()
        .expect("Configuration not initialized")
        .get::<config::Value>(key)
        .unwrap()
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

fn config_value_to_json(val: &config::Value) -> serde_json::Value {
    match &val.kind {
        ValueKind::Nil => serde_json::Value::Null,
        ValueKind::Boolean(b) => serde_json::Value::Bool(*b),
        ValueKind::I64(i) => serde_json::Value::Number(serde_json::Number::from(*i)),
        ValueKind::U64(i) => serde_json::Value::Number(serde_json::Number::from(*i)),
        ValueKind::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        ValueKind::String(s) => serde_json::Value::String(s.clone()),
        ValueKind::Array(arr) => {
            let vec = arr.iter().map(config_value_to_json).collect();
            serde_json::Value::Array(vec)
        }
        ValueKind::Table(map) => {
            let obj = map
                .iter()
                .map(|(k, v)| (k.clone(), config_value_to_json(v)))
                .collect();
            serde_json::Value::Object(obj)
        }
        _ => {
            panic!("Unsupported config value type: {:?}", val.kind);
        }
    }
}

pub fn get_config_json_map() -> Result<serde_json::Value, String> {
    let raw_map = get_config_map()?;

    let obj = raw_map
        .iter()
        .map(|(k, v)| (k.clone(), config_value_to_json(v)))
        .collect();

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
