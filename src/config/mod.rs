#![allow(unused_imports)]
use config::{Config, File, FileFormat, Source, Value};
use lazy_static::lazy_static;

lazy_static! {
    #[derive(Debug)]
    static ref _CONFIG_LOADED: Config = {
        Config::builder()
            .add_source(File::new("./bindizr.conf", FileFormat::Ini).required(true))
            .build()
            .expect("Failed to build configuration")
        };
}

pub(crate) fn initialize() {
    lazy_static::initialize(&_CONFIG_LOADED);

    println!("Configuration loaded successfully");

    // Debug: Print the loaded configuration
    // for (key, value) in _CONFIG_LOADED.collect().unwrap() {
    //     println!("{} = {}", key, value);
    // }
}

pub(crate) fn get_config(key: &str) -> String {
    _CONFIG_LOADED
        .get::<Value>(key)
        .unwrap_or_else(|_| panic!("Configuration key '{}' not found", key))
        .into_string()
        .unwrap_or_else(|_| panic!("Configuration key '{}' is not a string", key))
}
