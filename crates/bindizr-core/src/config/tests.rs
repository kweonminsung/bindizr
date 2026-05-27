use config::{Config, File, FileFormat};
use std::fs::File as StdFile;
use std::io::Write;
use tempfile::tempdir;

use crate::config::{DatabaseType, parse_bindizr_config};

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
    let (dir, config_path) = create_temp_config_file("[test]\nint_value = 42\nfloat_value = 3.15");

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
    assert!((float_value - 3.15).abs() < f64::EPSILON);

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
fn test_parse_bindizr_config_success() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "127.0.0.1"

[api]
listen_port = 3000
require_authentication = false

[database]
type = "sqlite"

[database.mysql]
server_url = ""

[database.sqlite]
file_path = "file::memory:?cache=shared"

[database.postgresql]
server_url = ""

[dns]
listen_port = 53
secondary_addrs = "127.0.0.1:53"
nsupdate_tsig_key = ""

[logging]
log_level = "debug"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let parsed = parse_bindizr_config(config).unwrap();

    assert_eq!(parsed.listen_addr.to_string(), "127.0.0.1");
    assert!(matches!(
        parsed.database.database_type,
        DatabaseType::Sqlite
    ));
    assert_eq!(parsed.api.listen_port, 3000);

    drop(dir);
}

#[test]
fn test_parse_bindizr_config_defaults_missing_nsupdate_tsig_key() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "127.0.0.1"

[api]
listen_port = 3000
require_authentication = false

[database]
type = "sqlite"

[database.mysql]
server_url = ""

[database.sqlite]
file_path = "file::memory:?cache=shared"

[database.postgresql]
server_url = ""

[dns]
listen_port = 53
secondary_addrs = "127.0.0.1:53"

[logging]
log_level = "debug"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let parsed = parse_bindizr_config(config).unwrap();

    assert_eq!(parsed.dns.nsupdate_tsig_key, "");

    drop(dir);
}

#[test]
fn test_parse_bindizr_config_defaults_unselected_database_sections() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "127.0.0.1"

[api]
listen_port = 3000
require_authentication = false

[database]
type = "sqlite"

[database.sqlite]
file_path = "file::memory:?cache=shared"

[dns]
listen_port = 53
secondary_addrs = "127.0.0.1:53"
nsupdate_tsig_key = ""

[logging]
log_level = "debug"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let parsed = parse_bindizr_config(config).unwrap();

    assert_eq!(
        parsed.database.sqlite.file_path,
        "file::memory:?cache=shared"
    );
    assert_eq!(parsed.database.mysql.server_url, "");
    assert_eq!(parsed.database.postgresql.server_url, "");

    drop(dir);
}

#[test]
fn test_parse_bindizr_config_rejects_invalid_listen_addr() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "not-an-ip"

[api]
listen_port = 3000
require_authentication = false

[database]
type = "sqlite"

[database.mysql]
server_url = ""

[database.sqlite]
file_path = "file::memory:?cache=shared"

[database.postgresql]
server_url = ""

[dns]
listen_port = 53
secondary_addrs = ""
nsupdate_tsig_key = ""

[logging]
log_level = "debug"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let err = parse_bindizr_config(config).unwrap_err();

    assert!(err.contains("Invalid Bindizr configuration"));

    drop(dir);
}

#[test]
fn test_parse_bindizr_config_rejects_empty_selected_database_url() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "127.0.0.1"

[api]
listen_port = 3000
require_authentication = false

[database]
type = "mysql"

[database.mysql]
server_url = ""

[database.sqlite]
file_path = "file::memory:?cache=shared"

[database.postgresql]
server_url = ""

[dns]
listen_port = 53
secondary_addrs = ""
nsupdate_tsig_key = ""

[logging]
log_level = "debug"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let err = parse_bindizr_config(config).unwrap_err();

    assert!(err.contains("database.mysql.server_url must not be empty"));

    drop(dir);
}
