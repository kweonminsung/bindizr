use config::{Config, File, FileFormat};

use crate::config::{
    BINDIZR_CONF_PATH, BindizrConfig, DatabaseType, LogLevel, apply_env_overrides_from,
    parse_bindizr_config_with_env, resolve_config_path_with_env,
};

/// Deviations from the base config TOML; the default renders a minimal valid
/// sqlite config.
struct TestConfigToml {
    api_listen_addr: &'static str,
    require_authentication: bool,
    /// Renders `external_dns_enabled` in `[api]` when set; `None` omits it.
    api_external_dns_enabled: Option<bool>,
    database_type: &'static str,
    /// Include the `[database.mysql]` / `[database.postgresql]` sections.
    unselected_databases: bool,
    secondary_addrs: &'static str,
    /// Extra `[dns]` lines (newline-separated, no trailing newline).
    dns_notify: &'static str,
    /// Renders a `[dnssec]` section with these lines when non-empty.
    dnssec: &'static str,
}

impl Default for TestConfigToml {
    fn default() -> Self {
        Self {
            api_listen_addr: "127.0.0.1",
            require_authentication: false,
            api_external_dns_enabled: None,
            database_type: "sqlite",
            unselected_databases: true,
            secondary_addrs: "",
            dns_notify: "",
            dnssec: "",
        }
    }
}

impl TestConfigToml {
    fn render(&self) -> String {
        let unselected_databases = if self.unselected_databases {
            "\n[database.mysql]\nserver_url = \"\"\n\n[database.postgresql]\nserver_url = \"\"\n"
        } else {
            ""
        };
        let api_external_dns = self
            .api_external_dns_enabled
            .map(|value| format!("external_dns_enabled = {}\n", value))
            .unwrap_or_default();
        let dnssec = if self.dnssec.is_empty() {
            String::new()
        } else {
            format!("\n[dnssec]\n{}\n", self.dnssec)
        };
        format!(
            r#"
[api]
listen_addr = "{api_listen_addr}"
listen_port = 3000
require_authentication = {require_authentication}
{api_external_dns}
[database]
type = "{database_type}"

[database.sqlite]
file_path = "file::memory:?cache=shared"
{unselected_databases}
[dns]
listen_addr = "127.0.0.1"
listen_port = 53
secondary_addrs = "{secondary_addrs}"
{dns_notify}{dnssec}
[logging]
log_level = "debug"
"#,
            api_listen_addr = self.api_listen_addr,
            require_authentication = self.require_authentication,
            api_external_dns = api_external_dns,
            database_type = self.database_type,
            secondary_addrs = self.secondary_addrs,
            dns_notify = self.dns_notify,
            dnssec = dnssec,
        )
    }
}

fn parse_config(toml: &TestConfigToml) -> Result<BindizrConfig, String> {
    let config = Config::builder()
        .add_source(File::from_str(&toml.render(), FileFormat::Toml))
        .build()
        .unwrap();
    parse_bindizr_config_with_env(config, |_| None)
}

#[test]
fn parse_bindizr_config_accepts_valid_config() {
    let parsed = parse_config(&TestConfigToml {
        secondary_addrs: "127.0.0.1:53",
        dns_notify: "notify_after_update = false\nnotify_on_startup = true\nnotify_retries = 4\nnotify_timeout_secs = 9\nnsupdate_allow_unsigned = true",
        ..Default::default()
    })
    .unwrap();

    assert_eq!(parsed.api.listen_addr.to_string(), "127.0.0.1");
    assert_eq!(parsed.dns.listen_addr.to_string(), "127.0.0.1");
    assert!(matches!(
        parsed.database.database_type,
        DatabaseType::Sqlite
    ));
    assert_eq!(parsed.api.listen_port, 3000);
    assert!(!parsed.dns.notify_after_update);
    assert!(parsed.dns.notify_on_startup);
    assert_eq!(parsed.dns.notify_retries, 4);
    assert_eq!(parsed.dns.notify_timeout_secs, 9);
    assert!(parsed.dns.nsupdate_allow_unsigned);
}

#[test]
fn parse_bindizr_config_defaults_missing_optional_dns_fields() {
    let parsed = parse_config(&TestConfigToml::default()).unwrap();

    assert!(parsed.dns.notify_after_update);
    assert!(!parsed.dns.notify_on_startup);
    assert_eq!(parsed.dns.notify_retries, 3);
    assert_eq!(parsed.dns.notify_timeout_secs, 5);
    assert!(!parsed.dns.nsupdate_allow_unsigned);
}

#[test]
fn parse_bindizr_config_defaults_dnssec_and_journal_retention() {
    let parsed = parse_config(&TestConfigToml::default()).unwrap();

    assert_eq!(parsed.dnssec.default_signature_validity_days, 14);
    assert_eq!(parsed.dnssec.default_signature_refresh_days, 5);
    assert_eq!(parsed.dnssec.rollover_publish_holddown_secs, 86_400);
    assert_eq!(parsed.dnssec.rollover_retire_holddown_secs, 172_800);
    assert_eq!(parsed.dns.journal_retention_days, 365);
}

#[test]
fn parse_bindizr_config_accepts_custom_dnssec_section() {
    let parsed = parse_config(&TestConfigToml {
        dnssec: "default_signature_validity_days = 30\ndefault_signature_refresh_days = 10",
        ..Default::default()
    })
    .unwrap();

    assert_eq!(parsed.dnssec.default_signature_validity_days, 30);
    assert_eq!(parsed.dnssec.default_signature_refresh_days, 10);
}

#[test]
fn parse_bindizr_config_rejects_refresh_not_below_validity() {
    let err = parse_config(&TestConfigToml {
        dnssec: "default_signature_validity_days = 5\ndefault_default_signature_refresh_days = 5",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("default_signature_refresh_days"), "got: {err}");
}

#[test]
fn parse_bindizr_config_rejects_validity_beyond_serial_arithmetic_range() {
    // RFC 4034, Section 3.1.5: serial arithmetic wraps at 2^31 seconds.
    let err = parse_config(&TestConfigToml {
        dnssec: "default_signature_validity_days = 24856
default_default_signature_refresh_days = 5",
        ..Default::default()
    })
    .unwrap_err();
    assert!(
        err.contains("default_signature_validity_days"),
        "got: {err}"
    );

    parse_config(&TestConfigToml {
        dnssec: "default_signature_validity_days = 24855
default_default_signature_refresh_days = 5",
        ..Default::default()
    })
    .unwrap();
}

#[test]
fn apply_env_overrides_covers_dnssec_and_journal_retention() {
    let config = Config::builder()
        .add_source(File::from_str(
            &TestConfigToml::default().render(),
            FileFormat::Toml,
        ))
        .build()
        .unwrap();
    let parsed = parse_bindizr_config_with_env(config, |name| match name {
        "BINDIZR_DNSSEC_DEFAULT_SIGNATURE_VALIDITY_DAYS" => Some("21".to_string()),
        "BINDIZR_DNSSEC_DEFAULT_SIGNATURE_REFRESH_DAYS" => Some("7".to_string()),
        "BINDIZR_JOURNAL_RETENTION_DAYS" => Some("0".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(parsed.dnssec.default_signature_validity_days, 21);
    assert_eq!(parsed.dnssec.default_signature_refresh_days, 7);
    assert_eq!(parsed.dns.journal_retention_days, 0);
}

#[test]
fn parse_bindizr_config_defaults_metrics_enabled_to_true() {
    let parsed = parse_config(&TestConfigToml::default()).unwrap();

    assert!(parsed.api.metrics_enabled);
}

#[test]
fn parse_bindizr_config_defaults_external_dns_to_disabled() {
    let parsed = parse_config(&TestConfigToml::default()).unwrap();

    assert!(!parsed.api.external_dns_enabled);
}

#[test]
fn parse_bindizr_config_accepts_external_dns_enabled() {
    let parsed = parse_config(&TestConfigToml {
        api_external_dns_enabled: Some(true),
        ..Default::default()
    })
    .unwrap();

    assert!(parsed.api.external_dns_enabled);
}

#[test]
fn parse_bindizr_config_defaults_unselected_database_sections() {
    let parsed = parse_config(&TestConfigToml {
        unselected_databases: false,
        ..Default::default()
    })
    .unwrap();

    assert_eq!(
        parsed.database.sqlite.file_path,
        "file::memory:?cache=shared"
    );
    assert_eq!(parsed.database.mysql.server_url, "");
    assert_eq!(parsed.database.postgresql.server_url, "");
}

#[test]
fn parse_bindizr_config_rejects_invalid_listen_addr() {
    let err = parse_config(&TestConfigToml {
        api_listen_addr: "not-an-ip",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("Invalid Bindizr configuration"));
}

#[test]
fn parse_bindizr_config_rejects_empty_selected_database_url() {
    let err = parse_config(&TestConfigToml {
        database_type: "mysql",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("database.mysql.server_url must not be empty"));
}

#[test]
fn apply_env_overrides_replaces_config_values_before_validation() {
    let mut overridden = parse_config(&TestConfigToml {
        require_authentication: true,
        ..Default::default()
    })
    .unwrap();

    apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_API_LISTEN_ADDR" => Some("0.0.0.0".to_string()),
        "BINDIZR_API_PORT" => Some("8000".to_string()),
        "BINDIZR_API_REQUIRE_AUTHENTICATION" => Some("false".to_string()),
        "BINDIZR_API_METRICS_ENABLED" => Some("false".to_string()),
        "BINDIZR_API_EXTERNAL_DNS_ENABLED" => Some("true".to_string()),
        "BINDIZR_DATABASE_TYPE" => Some("mysql".to_string()),
        "BINDIZR_DATABASE_URL" => Some("mysql://user:p#ss&word@mysql:3306/bindizr".to_string()),
        "BINDIZR_DNS_LISTEN_ADDR" => Some("127.0.0.2".to_string()),
        "BINDIZR_DNS_PORT" => Some("5353".to_string()),
        "BINDIZR_SECONDARY_ADDRS" => Some("192.0.2.10:53,192.0.2.11:53".to_string()),
        "BINDIZR_NSUPDATE_ALLOW_UNSIGNED" => Some("true".to_string()),
        "BINDIZR_NOTIFY_AFTER_UPDATE" => Some("false".to_string()),
        "BINDIZR_NOTIFY_ON_STARTUP" => Some("true".to_string()),
        "BINDIZR_NOTIFY_RETRIES" => Some("7".to_string()),
        "BINDIZR_NOTIFY_TIMEOUT_SECS" => Some("11".to_string()),
        "BINDIZR_LOG_LEVEL" => Some("info".to_string()),
        _ => None,
    })
    .unwrap();

    assert_eq!(overridden.api.listen_addr.to_string(), "0.0.0.0");
    assert_eq!(overridden.api.listen_port, 8000);
    assert!(!overridden.api.require_authentication);
    assert!(!overridden.api.metrics_enabled);
    assert!(overridden.api.external_dns_enabled);
    assert!(matches!(
        overridden.database.database_type,
        DatabaseType::Mysql
    ));
    assert_eq!(
        overridden.database.mysql.server_url,
        "mysql://user:p#ss&word@mysql:3306/bindizr"
    );
    assert_eq!(overridden.dns.listen_addr.to_string(), "127.0.0.2");
    assert_eq!(overridden.dns.listen_port, 5353);
    assert_eq!(
        overridden.dns.secondary_addrs,
        "192.0.2.10:53,192.0.2.11:53"
    );
    assert!(overridden.dns.nsupdate_allow_unsigned);
    assert!(!overridden.dns.notify_after_update);
    assert!(overridden.dns.notify_on_startup);
    assert_eq!(overridden.dns.notify_retries, 7);
    assert_eq!(overridden.dns.notify_timeout_secs, 11);
    assert!(matches!(overridden.logging.log_level, LogLevel::Info));
}

#[test]
fn apply_env_overrides_rejects_invalid_values() {
    let mut overridden = parse_config(&TestConfigToml {
        unselected_databases: false,
        ..Default::default()
    })
    .unwrap();

    let err = apply_env_overrides_from(&mut overridden, |name| match name {
        "BINDIZR_API_PORT" => Some("not-a-port".to_string()),
        _ => None,
    })
    .unwrap_err();

    assert!(err.contains("Invalid BINDIZR_API_PORT environment variable"));
}

#[test]
fn resolve_config_path_prefers_argument_then_env_then_default() {
    let env = |name: &str| (name == "BINDIZR_CONFIG_PATH").then(|| "/env/path.toml".to_string());

    assert_eq!(
        resolve_config_path_with_env(Some("/arg/path.toml"), env),
        "/arg/path.toml"
    );
    assert_eq!(resolve_config_path_with_env(None, env), "/env/path.toml");
    assert_eq!(
        resolve_config_path_with_env(None, |_| None),
        BINDIZR_CONF_PATH
    );
}

#[test]
fn parse_bindizr_config_rejects_entryless_secondary_addrs() {
    let err = parse_config(&TestConfigToml {
        secondary_addrs: ",",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("dns.secondary_addrs contains no addresses"));
}
