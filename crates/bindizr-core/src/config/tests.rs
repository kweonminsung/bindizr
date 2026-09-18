use crate::config::{
    BINDIZR_CONF_PATH, BindizrConfig, DatabaseType, LogFormat, LogLevel, load_initial_token_file,
    resolve_config_path_with_env,
};

/// Deviations from the base config TOML; the default renders a minimal valid
/// sqlite config.
struct TestConfigToml {
    api_listen_addr: &'static str,
    authentication_required: bool,
    database_type: &'static str,
    /// Include the `[database.mysql]` / `[database.postgresql]` sections.
    unselected_databases: bool,
    secondary_addrs: &'static str,
    /// Extra lines after the `[dns]` keys (newline-separated, no trailing
    /// newline); a `[dns.*]` sub-table header may open one there.
    dns_extra: &'static str,
    api_listen_port: u16,
    dns_listen_port: u16,
}

impl Default for TestConfigToml {
    /// Build a valid configuration fixture with default section values.
    fn default() -> Self {
        Self {
            api_listen_addr: "127.0.0.1",
            authentication_required: false,
            database_type: "sqlite",
            unselected_databases: true,
            secondary_addrs: "",
            dns_extra: "",
            api_listen_port: 3000,
            dns_listen_port: 53,
        }
    }
}

impl TestConfigToml {
    /// Render the configuration fixture as TOML.
    fn render(&self) -> String {
        let unselected_databases = if self.unselected_databases {
            "\n[database.mysql]\nurl = \"\"\n\n[database.postgresql]\nurl = \"\"\n"
        } else {
            ""
        };
        format!(
            r#"
[api]
listen_addr = "{api_listen_addr}"
listen_port = {api_listen_port}

[api.authentication]
required = {authentication_required}

[database]
type = "{database_type}"

[database.sqlite]
file_path = "file::memory:?cache=shared"
{unselected_databases}
[dns]
listen_addr = "127.0.0.1"
listen_port = {dns_listen_port}
secondary_addrs = "{secondary_addrs}"
{dns_extra}
[logging]
level = "debug"
"#,
            api_listen_addr = self.api_listen_addr,
            authentication_required = self.authentication_required,
            database_type = self.database_type,
            secondary_addrs = self.secondary_addrs,
            dns_extra = self.dns_extra,
            api_listen_port = self.api_listen_port,
            dns_listen_port = self.dns_listen_port,
        )
    }
}

/// Parse a TOML configuration fixture.
fn parse_config(toml: &TestConfigToml) -> Result<BindizrConfig, String> {
    BindizrConfig::from_toml(&toml.render(), |_| None)
}

/// Verify that `from_toml` accepts valid config.
#[test]
fn from_toml_accepts_valid_config() {
    let parsed = parse_config(&TestConfigToml {
        secondary_addrs: "127.0.0.1:53",
        dns_extra: "[dns.nsupdate]\ntsig_required = false\n\n[dns.notify]\nafter_update = false\non_startup = true\nretries = 4\ntimeout_secs = 9",
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
    assert!(!parsed.dns.notify.after_update);
    assert!(parsed.dns.notify.on_startup);
    assert_eq!(parsed.dns.notify.retries, 4);
    assert_eq!(parsed.dns.notify.timeout_secs, 9);
    assert!(!parsed.dns.nsupdate.tsig_required);
}

/// Verify that `from_toml` defaults missing optional fields.
#[test]
fn from_toml_defaults_missing_optional_fields() {
    let parsed = parse_config(&TestConfigToml::default()).unwrap();

    assert!(parsed.api.metrics_enabled);
    assert!(!parsed.api.external_dns_enabled);
    assert!(parsed.dns.notify.after_update);
    assert!(!parsed.dns.notify.on_startup);
    // 0 keeps NOTIFY ahead of the write's answer; only a window queues it.
    assert_eq!(parsed.dns.notify.batch_ms, 0);
    assert_eq!(parsed.dns.notify.retries, 3);
    assert_eq!(parsed.dns.notify.timeout_secs, 3);
    assert!(parsed.dns.transfer_cache.enabled);
    assert_eq!(parsed.dns.transfer_cache.max_records, 500_000);
    assert!(parsed.dns.nsupdate.tsig_required);
    assert_eq!(parsed.dns.zone_history_retention_days, 365);
    assert_eq!(parsed.dns.scheduler_interval_secs, 3600);
    assert_eq!(parsed.logging.format, LogFormat::Text);
}

/// Verify that `from_toml` defaults the fields of a sub-table left empty.
#[test]
fn from_toml_defaults_fields_of_an_empty_sub_table() {
    // The sample file keeps every sub-table header and comments out the
    // keys, so a header with nothing under it must read as the defaults.
    let parsed = parse_config(&TestConfigToml {
        dns_extra: "[dns.notify]\n\n[dns.transfer_cache]\nmax_records = 10",
        ..Default::default()
    })
    .unwrap();

    assert_eq!(parsed.dns.notify, Default::default());
    assert!(parsed.dns.transfer_cache.enabled);
    assert_eq!(parsed.dns.transfer_cache.max_records, 10);
}

/// Verify that `from_toml` rejects a key it does not know.
#[test]
fn from_toml_rejects_an_unknown_key() {
    // A mistyped key would otherwise be dropped and the default applied.
    let err = parse_config(&TestConfigToml {
        dns_extra: "listen_prot = 5300",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("unknown field `listen_prot`"), "{}", err);
}

/// Verify that `from_toml` defaults unselected database sections.
#[test]
fn from_toml_defaults_unselected_database_sections() {
    let parsed = parse_config(&TestConfigToml {
        unselected_databases: false,
        ..Default::default()
    })
    .unwrap();

    assert_eq!(
        parsed.database.sqlite.file_path,
        "file::memory:?cache=shared"
    );
    assert_eq!(parsed.database.mysql.url, "");
    assert_eq!(parsed.database.postgresql.url, "");
}

/// Verify that `from_toml` rejects invalid listen addr.
#[test]
fn from_toml_rejects_invalid_listen_addr() {
    let err = parse_config(&TestConfigToml {
        api_listen_addr: "not-an-ip",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("Invalid Bindizr configuration"));
}

/// Verify that `from_toml` rejects empty selected database url.
#[test]
fn from_toml_rejects_empty_selected_database_url() {
    let err = parse_config(&TestConfigToml {
        database_type: "mysql",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("database.mysql.url must not be empty"));
}

/// Verify that `apply_env_overrides` replaces config values before validation.
#[test]
fn apply_env_overrides_replaces_config_values_before_validation() {
    let mut overridden = parse_config(&TestConfigToml {
        authentication_required: true,
        ..Default::default()
    })
    .unwrap();

    overridden
        .apply_env_overrides(|name| match name {
            "BINDIZR_API_LISTEN_ADDR" => Some("0.0.0.0".to_string()),
            "BINDIZR_API_LISTEN_PORT" => Some("8000".to_string()),
            "BINDIZR_API_AUTHENTICATION_REQUIRED" => Some("false".to_string()),
            "BINDIZR_API_AUTHENTICATION_INITIAL_TOKEN_FILE" => {
                Some("/run/secrets/token".to_string())
            }
            "BINDIZR_API_METRICS_ENABLED" => Some("false".to_string()),
            "BINDIZR_API_EXTERNAL_DNS_ENABLED" => Some("true".to_string()),
            "BINDIZR_DATABASE_TYPE" => Some("mysql".to_string()),
            "BINDIZR_DATABASE_URL" => Some("mysql://user:p#ss&word@mysql:3306/bindizr".to_string()),
            "BINDIZR_DNS_LISTEN_ADDR" => Some("127.0.0.2".to_string()),
            "BINDIZR_DNS_LISTEN_PORT" => Some("5353".to_string()),
            "BINDIZR_DNS_SECONDARY_ADDRS" => Some("192.0.2.10:53,192.0.2.11:53".to_string()),
            "BINDIZR_DNS_NSUPDATE_TSIG_REQUIRED" => Some("false".to_string()),
            "BINDIZR_DNS_NOTIFY_AFTER_UPDATE" => Some("false".to_string()),
            "BINDIZR_DNS_NOTIFY_ON_STARTUP" => Some("true".to_string()),
            "BINDIZR_DNS_NOTIFY_BATCH_MS" => Some("50".to_string()),
            "BINDIZR_DNS_NOTIFY_RETRIES" => Some("7".to_string()),
            "BINDIZR_DNS_NOTIFY_TIMEOUT_SECS" => Some("11".to_string()),
            "BINDIZR_DNS_TRANSFER_CACHE_ENABLED" => Some("false".to_string()),
            "BINDIZR_DNS_ZONE_HISTORY_RETENTION_DAYS" => Some("0".to_string()),
            "BINDIZR_DNS_SCHEDULER_INTERVAL_SECS" => Some("0".to_string()),
            "BINDIZR_DNS_ZONE_DEFAULTS_TTL" => Some("600".to_string()),
            "BINDIZR_LOGGING_LEVEL" => Some("info".to_string()),
            "BINDIZR_LOGGING_FORMAT" => Some("json".to_string()),
            _ => None,
        })
        .unwrap();

    assert_eq!(overridden.api.listen_addr.to_string(), "0.0.0.0");
    assert_eq!(overridden.api.listen_port, 8000);
    assert!(!overridden.api.authentication.required);
    assert_eq!(
        overridden.api.authentication.initial_token_file.as_deref(),
        Some("/run/secrets/token")
    );
    assert!(!overridden.api.metrics_enabled);
    assert!(overridden.api.external_dns_enabled);
    assert!(matches!(
        overridden.database.database_type,
        DatabaseType::Mysql
    ));
    assert_eq!(
        overridden.database.mysql.url,
        "mysql://user:p#ss&word@mysql:3306/bindizr"
    );
    assert_eq!(overridden.dns.listen_addr.to_string(), "127.0.0.2");
    assert_eq!(overridden.dns.listen_port, 5353);
    assert_eq!(
        overridden.dns.secondary_addrs,
        "192.0.2.10:53,192.0.2.11:53"
    );
    assert!(!overridden.dns.nsupdate.tsig_required);
    assert!(!overridden.dns.notify.after_update);
    assert!(overridden.dns.notify.on_startup);
    assert_eq!(overridden.dns.notify.batch_ms, 50);
    assert_eq!(overridden.dns.notify.retries, 7);
    assert_eq!(overridden.dns.notify.timeout_secs, 11);
    assert!(!overridden.dns.transfer_cache.enabled);
    assert_eq!(overridden.dns.zone_history_retention_days, 0);
    // 0 is the off switch, not a rejected value.
    assert_eq!(overridden.dns.scheduler_interval_secs, 0);
    assert_eq!(overridden.dns.zone_defaults.ttl, 600);
    assert!(matches!(overridden.logging.level, LogLevel::Info));
    assert_eq!(overridden.logging.format, LogFormat::Json);
}

/// Verify that `apply_env_overrides` rejects invalid values.
#[test]
fn apply_env_overrides_rejects_invalid_values() {
    let mut overridden = parse_config(&TestConfigToml {
        unselected_databases: false,
        ..Default::default()
    })
    .unwrap();

    let err = overridden
        .apply_env_overrides(|name| match name {
            "BINDIZR_API_LISTEN_PORT" => Some("not-a-port".to_string()),
            _ => None,
        })
        .unwrap_err();

    assert!(err.contains("Invalid BINDIZR_API_LISTEN_PORT environment variable"));
}

/// Verify that `resolve_config_path` prefers argument then env then default.
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

/// Verify that `from_toml` rejects entryless secondary addrs.
#[test]
fn from_toml_rejects_entryless_secondary_addrs() {
    let err = parse_config(&TestConfigToml {
        secondary_addrs: ",",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("dns.secondary_addrs contains no addresses"));
}

/// Verify that `from_toml` rejects port zero.
#[test]
fn from_toml_rejects_port_zero() {
    // Port 0 binds an ephemeral one, somewhere no client could find.
    let err = parse_config(&TestConfigToml {
        dns_listen_port: 0,
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.contains("dns.listen_port must not be 0"), "{}", err);

    let err = parse_config(&TestConfigToml {
        api_listen_port: 0,
        ..Default::default()
    })
    .unwrap_err();
    assert!(err.contains("api.listen_port must not be 0"), "{}", err);
}

/// Verify that `from_toml` rejects listeners sharing a port.
#[test]
fn from_toml_rejects_listeners_sharing_a_port() {
    let err = parse_config(&TestConfigToml {
        api_listen_port: 5353,
        dns_listen_port: 5353,
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("cannot share port 5353"), "{}", err);
}

/// Verify that `from_toml` rejects an unparseable secondary address.
#[test]
fn from_toml_rejects_an_unparseable_secondary_address() {
    let err = parse_config(&TestConfigToml {
        secondary_addrs: "192.0.2.1, not a host",
        ..Default::default()
    })
    .unwrap_err();

    assert!(err.contains("is not a host[:port] address"), "{}", err);
}

/// Verify that a reload refuses what a running process cannot adopt.
#[test]
fn a_reload_refuses_what_a_running_process_cannot_adopt() {
    // authentication.required is in the list because the router is built
    // once: a section is fixed whole, not field by field.
    let current = parse_config(&TestConfigToml::default()).unwrap();

    let mut api_moved = current.clone();
    api_moved.api.listen_port += 1;
    assert_eq!(current.fixed_settings_changed(&api_moved), ["api"]);

    let mut auth_toggled = current.clone();
    auth_toggled.api.authentication.required = !current.api.authentication.required;
    assert_eq!(current.fixed_settings_changed(&auth_toggled), ["api"]);

    let mut db_moved = current.clone();
    db_moved.database.database_type = DatabaseType::Mysql;
    assert_eq!(current.fixed_settings_changed(&db_moved), ["database"]);

    let mut dns_moved = current.clone();
    dns_moved.dns.listen_port += 1;
    assert_eq!(
        current.fixed_settings_changed(&dns_moved),
        ["dns.listen_port"]
    );
}

/// Verify that a reload takes the settings read per use.
#[test]
fn a_reload_takes_the_settings_read_per_use() {
    let current = parse_config(&TestConfigToml::default()).unwrap();

    let mut next = current.clone();
    next.dns.secondary_addrs = "192.0.2.1:53".to_string();
    next.logging.level = LogLevel::Warn;

    assert!(current.fixed_settings_changed(&next).is_empty());
    assert_eq!(current.changed_settings(&next), ["dns", "logging"]);
    assert!(current.changed_settings(&current).is_empty());
}

/// Verify that a provisioned token file reads as the secret it holds.
#[test]
fn load_initial_token_file_trims_and_reads_an_empty_file_as_unset() {
    let dir = tempfile::tempdir().expect("temp dir");

    // A secret manager writes a trailing newline; the token must not carry it.
    let path = dir.path().join("token");
    std::fs::write(&path, "a-16-plus-secret\n").expect("write");
    assert_eq!(
        load_initial_token_file(path.to_str().unwrap()).unwrap(),
        Some("a-16-plus-secret".to_string())
    );

    // A mount that exists but was never filled must not seed an empty token.
    let empty = dir.path().join("empty");
    std::fs::write(&empty, "  \n").expect("write");
    assert_eq!(
        load_initial_token_file(empty.to_str().unwrap()).unwrap(),
        None
    );

    assert!(load_initial_token_file(dir.path().join("absent").to_str().unwrap()).is_err());
}
