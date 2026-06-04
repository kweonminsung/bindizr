use config::{Config, File, FileFormat};
use std::fs::File as StdFile;
use std::io::Write;
use tempfile::tempdir;

use crate::config::{
    DatabaseType, LogLevel, apply_env_overrides_from, parse_bindizr_config_with_env,
};

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
notify_after_update = false
notify_on_startup = true
nsupdate_tsig_key = ""

[logging]
log_level = "debug"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();

    assert_eq!(parsed.listen_addr.to_string(), "127.0.0.1");
    assert!(matches!(
        parsed.database.database_type,
        DatabaseType::Sqlite
    ));
    assert_eq!(parsed.api.listen_port, 3000);
    assert!(!parsed.dns.notify_after_update);
    assert!(parsed.dns.notify_on_startup);

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

    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();

    assert_eq!(parsed.dns.nsupdate_tsig_key, "");
    assert!(parsed.dns.notify_after_update);
    assert!(!parsed.dns.notify_on_startup);

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

    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();

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

    let err = parse_bindizr_config_with_env(config, |_| None).unwrap_err();

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

    let err = parse_bindizr_config_with_env(config, |_| None).unwrap_err();

    assert!(err.contains("database.mysql.server_url must not be empty"));

    drop(dir);
}

#[test]
fn test_parse_bindizr_config_accepts_bindizr_database_url_env_override() {
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

    let parsed = parse_bindizr_config_with_env(config, |name| match name {
        "BINDIZR_DATABASE_URL" => Some("mysql://user:p#ss&word@mysql:3306/bindizr".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(
        parsed.database.mysql.server_url,
        "mysql://user:p#ss&word@mysql:3306/bindizr"
    );

    drop(dir);
}

#[test]
fn test_apply_env_overrides_replaces_config_values_before_validation() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "127.0.0.1"

[api]
listen_port = 3000
require_authentication = true

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

    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_LISTEN_ADDR" => Some("0.0.0.0".to_string()),
        "BINDIZR_API_PORT" => Some("8000".to_string()),
        "BINDIZR_API_REQUIRE_AUTHENTICATION" => Some("false".to_string()),
        "BINDIZR_DATABASE_TYPE" => Some("mysql".to_string()),
        "BINDIZR_DATABASE_URL" => Some("mysql://user:p#ss&word@mysql:3306/bindizr".to_string()),
        "BINDIZR_DNS_PORT" => Some("5353".to_string()),
        "BINDIZR_SECONDARY_ADDRS" => Some("192.0.2.10:53,192.0.2.11:53".to_string()),
        "BINDIZR_NSUPDATE_TSIG_KEY" => Some("secret#with&chars".to_string()),
        "BINDIZR_NOTIFY_AFTER_UPDATE" => Some("false".to_string()),
        "BINDIZR_NOTIFY_ON_STARTUP" => Some("true".to_string()),
        "BINDIZR_LOG_LEVEL" => Some("info".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(overridden.listen_addr.to_string(), "0.0.0.0");
    assert_eq!(overridden.api.listen_port, 8000);
    assert!(!overridden.api.require_authentication);
    assert!(matches!(
        overridden.database.database_type,
        DatabaseType::Mysql
    ));
    assert_eq!(
        overridden.database.mysql.server_url,
        "mysql://user:p#ss&word@mysql:3306/bindizr"
    );
    assert_eq!(overridden.dns.listen_port, 5353);
    assert_eq!(
        overridden.dns.secondary_addrs,
        "192.0.2.10:53,192.0.2.11:53"
    );
    assert_eq!(overridden.dns.nsupdate_tsig_key, "secret#with&chars");
    assert!(!overridden.dns.notify_after_update);
    assert!(overridden.dns.notify_on_startup);
    assert!(matches!(overridden.logging.log_level, LogLevel::Info));

    drop(dir);
}

#[test]
fn test_apply_env_overrides_rejects_invalid_values() {
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

    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();
    let err = apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_API_PORT" => Some("not-a-port".to_string()),
        _ => None,
    })
    .unwrap_err();

    assert!(err.contains("Invalid BINDIZR_API_PORT environment variable"));

    drop(dir);
}
