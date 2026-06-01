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

// Helper: minimal SQLite config content for override tests
fn sqlite_config_content() -> &'static str {
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
log_level = "info"
"#
}

fn build_config_from_content(content: &str) -> (tempfile::TempDir, config::Config) {
    let (dir, config_path) = create_temp_config_file(content);
    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();
    (dir, config)
}

// --- parse_database_type_env via apply_env_overrides_from ---

#[test]
fn test_apply_env_overrides_accepts_all_database_type_values() {
    for db_type in &["mysql", "postgresql", "sqlite"] {
        let (dir, config_path) = create_temp_config_file(sqlite_config_content());
        let config = Config::builder()
            .add_source(File::new(&config_path, FileFormat::Toml))
            .build()
            .unwrap();

        let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
        let mut overridden = parsed.clone();
        let db_type_val = db_type.to_string();

        apply_env_overrides_from(&mut overridden, |name| match name {
            "BINDIZR_DATABASE_TYPE" => Some(db_type_val.clone()),
            _ => None,
        })
        .unwrap();

        let type_str = format!("{}", overridden.database.database_type);
        assert_eq!(type_str, *db_type, "database type should be {}", db_type);

        drop(dir);
    }
}

#[test]
fn test_apply_env_overrides_rejects_invalid_database_type() {
    let (dir, config_path) = create_temp_config_file(sqlite_config_content());
    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    let err = apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_DATABASE_TYPE" => Some("mariadb".to_string()),
        _ => None,
    })
    .unwrap_err();

    assert!(
        err.contains("Invalid BINDIZR_DATABASE_TYPE"),
        "error was: {}",
        err
    );
    assert!(err.contains("mariadb"));

    drop(dir);
}

// --- parse_log_level_env via apply_env_overrides_from ---

#[test]
fn test_apply_env_overrides_accepts_all_log_level_values() {
    let levels = [
        ("trace", "trace"),
        ("debug", "debug"),
        ("info", "info"),
        ("warn", "warn"),
        ("error", "error"),
    ];

    for (env_val, expected_str) in &levels {
        let (dir, config_path) = create_temp_config_file(sqlite_config_content());
        let config = Config::builder()
            .add_source(File::new(&config_path, FileFormat::Toml))
            .build()
            .unwrap();

        let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
        let mut overridden = parsed.clone();
        let level_val = env_val.to_string();

        apply_env_overrides_from(&mut overridden, |name| match name {
            "BINDIZR_LOG_LEVEL" => Some(level_val.clone()),
            _ => None,
        })
        .unwrap();

        assert_eq!(
            overridden.logging.log_level.to_string(),
            *expected_str,
            "log level should be {}",
            expected_str
        );

        drop(dir);
    }
}

#[test]
fn test_apply_env_overrides_rejects_invalid_log_level() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    let err = apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_LOG_LEVEL" => Some("verbose".to_string()),
        _ => None,
    })
    .unwrap_err();

    assert!(
        err.contains("Invalid BINDIZR_LOG_LEVEL"),
        "error was: {}",
        err
    );
    assert!(err.contains("verbose"));

    drop(dir);
}

// --- TSIG_SECRET fallback ---

#[test]
fn test_apply_env_overrides_uses_tsig_secret_as_fallback_for_nsupdate_key() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    apply_env_overrides_from(&mut overridden, |name| match name {
        "TSIG_SECRET" => Some("my-tsig-secret".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(overridden.dns.nsupdate_tsig_key, "my-tsig-secret");

    drop(dir);
}

#[test]
fn test_apply_env_overrides_bindizr_nsupdate_takes_priority_over_tsig_secret() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_NSUPDATE_TSIG_KEY" => Some("bindizr-key".to_string()),
        "TSIG_SECRET" => Some("tsig-fallback".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(overridden.dns.nsupdate_tsig_key, "bindizr-key");

    drop(dir);
}

// --- BINDIZR_DATABASE_URL routing ---

#[test]
fn test_apply_env_overrides_bindizr_database_url_routes_to_postgresql() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "127.0.0.1"

[api]
listen_port = 3000
require_authentication = false

[database]
type = "postgresql"

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
log_level = "info"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let parsed = parse_bindizr_config_with_env(config, |name| match name {
        "BINDIZR_DATABASE_URL" => Some("postgresql://user:pass@pg:5432/db".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(
        parsed.database.postgresql.server_url,
        "postgresql://user:pass@pg:5432/db"
    );
    assert_eq!(parsed.database.mysql.server_url, "");

    drop(dir);
}

#[test]
fn test_apply_env_overrides_bindizr_database_url_is_ignored_for_sqlite() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |name| match name {
        "BINDIZR_DATABASE_URL" => Some("should-be-ignored".to_string()),
        _ => None,
    })
    .unwrap();

    // sqlite.file_path should remain unchanged
    assert_eq!(
        parsed.database.sqlite.file_path,
        "file::memory:?cache=shared"
    );

    drop(dir);
}

// --- Individual database URL env overrides ---

#[test]
fn test_apply_env_overrides_bindizr_mysql_server_url() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_MYSQL_SERVER_URL" => Some("mysql://root:pass@mysql:3306/bindizr".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(
        overridden.database.mysql.server_url,
        "mysql://root:pass@mysql:3306/bindizr"
    );

    drop(dir);
}

#[test]
fn test_apply_env_overrides_bindizr_postgresql_server_url() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_POSTGRESQL_SERVER_URL" => {
            Some("postgresql://user:pass@pg:5432/bindizr".to_string())
        }
        _ => None,
    })
    .unwrap();

    assert_eq!(
        overridden.database.postgresql.server_url,
        "postgresql://user:pass@pg:5432/bindizr"
    );

    drop(dir);
}

#[test]
fn test_apply_env_overrides_bindizr_sqlite_file_path() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_SQLITE_FILE_PATH" => Some("/var/lib/bindizr/bindizr.db".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(
        overridden.database.sqlite.file_path,
        "/var/lib/bindizr/bindizr.db"
    );

    drop(dir);
}

// --- Specific invalid env variable rejections ---

#[test]
fn test_apply_env_overrides_rejects_invalid_listen_addr() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    let err = apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_LISTEN_ADDR" => Some("not-an-ip".to_string()),
        _ => None,
    })
    .unwrap_err();

    assert!(
        err.contains("Invalid BINDIZR_LISTEN_ADDR"),
        "error was: {}",
        err
    );

    drop(dir);
}

#[test]
fn test_apply_env_overrides_rejects_invalid_dns_port() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    let err = apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_DNS_PORT" => Some("not-a-number".to_string()),
        _ => None,
    })
    .unwrap_err();

    assert!(
        err.contains("Invalid BINDIZR_DNS_PORT"),
        "error was: {}",
        err
    );

    drop(dir);
}

#[test]
fn test_apply_env_overrides_rejects_invalid_require_authentication() {
    let (dir, config) = build_config_from_content(sqlite_config_content());
    let parsed = parse_bindizr_config_with_env(config, |_| None).unwrap();
    let mut overridden = parsed.clone();

    let err = apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_API_REQUIRE_AUTHENTICATION" => Some("yes".to_string()),
        _ => None,
    })
    .unwrap_err();

    assert!(
        err.contains("Invalid BINDIZR_API_REQUIRE_AUTHENTICATION"),
        "error was: {}",
        err
    );

    drop(dir);
}

// --- Validation with env overrides ---

#[test]
fn test_parse_bindizr_config_with_env_rejects_empty_postgresql_url() {
    let (dir, config_path) = create_temp_config_file(
        r#"
listen_addr = "127.0.0.1"

[api]
listen_port = 3000
require_authentication = false

[database]
type = "postgresql"

[database.postgresql]
server_url = ""

[dns]
listen_port = 53
secondary_addrs = ""
nsupdate_tsig_key = ""

[logging]
log_level = "info"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    let err = parse_bindizr_config_with_env(config, |_| None).unwrap_err();

    assert!(
        err.contains("database.postgresql.server_url must not be empty"),
        "error was: {}",
        err
    );

    drop(dir);
}

#[test]
fn test_parse_bindizr_config_with_env_env_override_satisfies_validation() {
    // type=mysql with empty server_url in file, but BINDIZR_DATABASE_URL provides the URL
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

[dns]
listen_port = 53
secondary_addrs = ""
nsupdate_tsig_key = ""

[logging]
log_level = "info"
"#,
    );

    let config = Config::builder()
        .add_source(File::new(&config_path, FileFormat::Toml))
        .build()
        .unwrap();

    // Providing the URL via env should make validation pass
    let result = parse_bindizr_config_with_env(config, |name| match name {
        "BINDIZR_DATABASE_URL" => Some("mysql://root:pass@mysql:3306/bindizr".to_string()),
        _ => None,
    });

    assert!(result.is_ok(), "expected Ok but got: {:?}", result);

    drop(dir);
}
