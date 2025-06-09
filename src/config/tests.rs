use config::{Config, File, FileFormat};
use std::fs::File as StdFile;
use std::io::Write;
use tempfile::tempdir;

fn create_temp_config_file(content: &str) -> (tempfile::TempDir, String) {
    // Create a temporary directory
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("bindizr.conf");

    // Create a test config file
    let mut file = StdFile::create(&config_path).unwrap();
    write!(file, "{}", content).unwrap();
    file.flush().unwrap(); // Ensure content is written to disk

    // Return both the directory (to keep it alive) and the path
    (dir, config_path.to_str().unwrap().to_string())
}

#[test]
fn test_get_config_string() {
    let (dir, config_path) = create_temp_config_file("[test]\nstring_value = hello");

    // Create a config instance directly for testing
    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Ini))
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
        .add_source(File::new(&config_path, FileFormat::Ini))
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
        .add_source(File::new(&config_path, FileFormat::Ini))
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
