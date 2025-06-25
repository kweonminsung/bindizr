use config::{Config, File, FileFormat};
use std::fs::File as StdFile;
use std::io::Write;
use tempfile::tempdir;

use crate::config::config_value_to_json;

fn create_temp_config_file(content: &str) -> (tempfile::TempDir, String) {
    // Create a temporary directory
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("bindizr.conf.toml");

    // Create a test config file
    let mut file = StdFile::create(&config_path).unwrap();
    write!(file, "{}", content).unwrap();
    file.flush().unwrap(); // Ensure content is written to disk

    // Return both the directory (to keep it alive) and the path
    (dir, config_path.to_str().unwrap().to_string())
}

#[test]
fn test_get_config_string() {
    let (dir, config_path) = create_temp_config_file("[test]\nstring_value = \"hello\"");

    // Create a config instance directly for testing
    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    // Test string value retrieval
    let value: String = config.get("test.string_value").unwrap();
    assert_eq!(value, "hello");

    // Keep dir alive until the end of the test
    drop(dir);
}

#[test]
fn test_get_config_numeric() {
    let (dir, config_path) = create_temp_config_file("[test]\nint_value = 42\nfloat_value = 3.14");

    // Create a config instance directly for testing
    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    // Test integer value retrieval
    let int_value: i32 = config.get("test.int_value").unwrap();
    assert_eq!(int_value, 42);

    // Test float value retrieval
    let float_value: f64 = config.get("test.float_value").unwrap();
    assert_eq!(float_value, 3.14);

    // Keep dir alive until the end of the test
    drop(dir);
}

#[test]
fn test_get_config_boolean() {
    let (dir, config_path) =
        create_temp_config_file("[test]\nbool_true = true\nbool_false = false");

    // Create a config instance directly for testing
    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    // Test boolean value retrieval
    let bool_true: bool = config.get("test.bool_true").unwrap();
    assert!(bool_true);

    let bool_false: bool = config.get("test.bool_false").unwrap();
    assert!(!bool_false);

    // Keep dir alive until the end of the test
    drop(dir);
}

#[test]
fn test_config_value_to_json() {
    let (dir, config_path) = create_temp_config_file(
        "[test]\nstring_value = \"hello\"\nint_value = 42\nfloat_value = 3.14\nbool_value = true",
    );

    // Create a config instance directly for testing
    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    // Ensure the config is loaded
    let test_config = config.get::<config::Value>("test");
    assert!(test_config.is_ok());
    let test_config = test_config.unwrap();

    // Convert config values to JSON
    let json_map = config_value_to_json(&test_config);
    assert!(json_map.is_ok());
    let json_map = json_map.unwrap();

    // Check the JSON values
    assert_eq!(json_map["string_value"], "hello");
    assert_eq!(json_map["int_value"], 42);
    assert_eq!(json_map["float_value"], 3.14);
    assert_eq!(json_map["bool_value"], true);

    // Keep dir alive until the end of the test
    drop(dir);
}
