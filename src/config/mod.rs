use config::{Config, File, FileFormat, Value};
use lazy_static::lazy_static;

lazy_static! {
    static ref _CONFIG_LOADED: Config = {
        Config::builder()
            // .add_source(File::with_name("./bindizr.conf").required(true))
            .add_source(File::from_str(
                include_str!("../../bindizr.conf"),
                FileFormat::Ini,
            ))
            .build()
            .expect("Failed to build configuration")
    };

    // Debug: Print the loaded configuration

}

pub fn initialize() {
    lazy_static::initialize(&_CONFIG_LOADED);
}

pub fn get_config(key: &str) -> String {
    _CONFIG_LOADED
        .get::<Value>(key)
        .unwrap_or_else(|_| panic!("Configuration key '{}' not found", key))
        .into_string()
        .unwrap_or_else(|_| panic!("Configuration key '{}' is not a string", key))
}
