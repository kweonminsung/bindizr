#![allow(unused_imports)]
use std::any::type_name;

use config::{Config, File, FileFormat, Source, Value};
use lazy_static::lazy_static;

#[cfg(test)]
mod tests;

lazy_static! {
    #[derive(Debug)]
    static ref _CONFIG_LOADED: Config = {

        // println!("Configuration loaded successfully");

        Config::builder()
            .add_source(File::new("./bindizr.conf", FileFormat::Ini).required(true))
            .build()
            .expect("Failed to build configuration")
        };
}

pub(crate) fn initialize() {
    lazy_static::initialize(&_CONFIG_LOADED);

    // Debug: Print the loaded configuration
    // for (key, value) in _CONFIG_LOADED.collect().unwrap() {
    //     println!("{} = {}", key, value);
    // }
}

fn get_config_str(key: &str) -> String {
    _CONFIG_LOADED
        .get::<Value>(key)
        .unwrap()
        .into_string()
        .unwrap()
}

pub(crate) fn get_config<T: serde::de::DeserializeOwned>(key: &str) -> T {
    let value_str = get_config_str(key);

    serde_json::from_str::<T>(&value_str).unwrap_or_else(|e| {
        panic!(
            "Failed to parse configuration for '{}'. Expected type: {}. Error: {}",
            key,
            type_name::<T>(),
            e
        )
    })
}
