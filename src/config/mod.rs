use config::{Config, File, FileFormat, Source, Value};
use once_cell::sync::OnceCell;
use std::{any::type_name, collections::HashMap, str::FromStr};

// Config file path according to the platform
#[cfg(unix)]
pub const CONF_FILE_PATH: &str = "/etc/bindizr/bindizr.conf";
#[cfg(windows)]
pub const CONF_FILE_PATH: &str = "./bindizr.conf";

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
        .get::<Value>(key)
        .unwrap()
        .into_string()
        .unwrap()
}

pub fn get_config_map() -> Result<HashMap<String, Value>, String> {
    CONFIG
        .get()
        .ok_or_else(|| "Configuration not initialized".to_string())?
        .collect()
        .map_err(|e| format!("Failed to collect configuration: {}", e))
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
