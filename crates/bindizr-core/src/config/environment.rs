//! Environment overrides, applied before validation. A variable is `BINDIZR_`
//! plus the key's TOML path upper-cased with `_` for `.`; `BINDIZR_DATABASE_URL`
//! is the one convenience outside that rule.

use std::fmt;

use super::{BindizrConfig, DatabaseType};

impl BindizrConfig {
    /// Apply the `BINDIZR_*` environment variables to the loaded configuration.
    pub(crate) fn apply_env_overrides(
        &mut self,
        get_env: impl Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        if let Some(value) = get_env("BINDIZR_API_LISTEN_ADDR") {
            self.api.listen_addr = parse_env_value("BINDIZR_API_LISTEN_ADDR", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_LISTEN_PORT") {
            self.api.listen_port = parse_env_value("BINDIZR_API_LISTEN_PORT", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_AUTHENTICATION_REQUIRED") {
            self.api.authentication_required =
                parse_env_value("BINDIZR_API_AUTHENTICATION_REQUIRED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_METRICS_ENABLED") {
            self.api.metrics_enabled = parse_env_value("BINDIZR_API_METRICS_ENABLED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_EXTERNAL_DNS_ENABLED") {
            self.api.external_dns_enabled =
                parse_env_value("BINDIZR_API_EXTERNAL_DNS_ENABLED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_OPENAPI_ENABLED") {
            self.api.openapi_enabled = parse_env_value("BINDIZR_API_OPENAPI_ENABLED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_TLS_CERT_FILE") {
            self.api.tls_cert_file = to_optional_setting(value);
        }
        if let Some(value) = get_env("BINDIZR_API_TLS_KEY_FILE") {
            self.api.tls_key_file = to_optional_setting(value);
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_TYPE") {
            self.database.database_type = parse_env_value("BINDIZR_DATABASE_TYPE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_MYSQL_URL") {
            self.database.mysql.url = value;
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_POSTGRESQL_URL") {
            self.database.postgresql.url = value;
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_SQLITE_FILE_PATH") {
            self.database.sqlite.file_path = value;
        }
        // The generic URL overrides the selected backend's URL above; SQLite
        // continues to use its file path.
        if let Some(value) = get_env("BINDIZR_DATABASE_URL") {
            match self.database.database_type {
                DatabaseType::Mysql => self.database.mysql.url = value,
                DatabaseType::Postgresql => self.database.postgresql.url = value,
                DatabaseType::Sqlite => {}
            }
        }
        if let Some(value) = get_env("BINDIZR_DNS_LISTEN_ADDR") {
            self.dns.listen_addr = parse_env_value("BINDIZR_DNS_LISTEN_ADDR", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_LISTEN_PORT") {
            self.dns.listen_port = parse_env_value("BINDIZR_DNS_LISTEN_PORT", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_SECONDARY_ADDRS") {
            self.dns.secondary_addrs = value;
        }
        if let Some(value) = get_env("BINDIZR_DNS_NSUPDATE_TSIG_REQUIRED") {
            self.dns.nsupdate_tsig_required =
                parse_env_value("BINDIZR_DNS_NSUPDATE_TSIG_REQUIRED", &value)?;
        }
        // Three variables rather than one, because the key's name is part of
        // the contract: the client signs with it.
        if let Some(value) = get_env("BINDIZR_DNS_ZONE_HISTORY_RETENTION_DAYS") {
            self.dns.zone_history_retention_days =
                parse_env_value("BINDIZR_DNS_ZONE_HISTORY_RETENTION_DAYS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_SCHEDULER_INTERVAL_SECS") {
            self.dns.scheduler_interval_secs =
                parse_env_value("BINDIZR_DNS_SCHEDULER_INTERVAL_SECS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_NOTIFY_AFTER_UPDATE") {
            self.dns.notify.after_update =
                parse_env_value("BINDIZR_DNS_NOTIFY_AFTER_UPDATE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_NOTIFY_ON_STARTUP") {
            self.dns.notify.on_startup = parse_env_value("BINDIZR_DNS_NOTIFY_ON_STARTUP", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_NOTIFY_BATCH_MS") {
            self.dns.notify.batch_ms = parse_env_value("BINDIZR_DNS_NOTIFY_BATCH_MS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_NOTIFY_RETRIES") {
            self.dns.notify.retries = parse_env_value("BINDIZR_DNS_NOTIFY_RETRIES", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_NOTIFY_TIMEOUT_SECS") {
            self.dns.notify.timeout_secs =
                parse_env_value("BINDIZR_DNS_NOTIFY_TIMEOUT_SECS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_TRANSFER_CACHE_ENABLED") {
            self.dns.transfer_cache.enabled =
                parse_env_value("BINDIZR_DNS_TRANSFER_CACHE_ENABLED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_TRANSFER_CACHE_MAX_RECORDS") {
            self.dns.transfer_cache.max_records =
                parse_env_value("BINDIZR_DNS_TRANSFER_CACHE_MAX_RECORDS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_ZONE_DEFAULTS_TTL") {
            self.dns.zone_defaults.ttl = parse_env_value("BINDIZR_DNS_ZONE_DEFAULTS_TTL", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_ZONE_DEFAULTS_REFRESH") {
            self.dns.zone_defaults.refresh =
                parse_env_value("BINDIZR_DNS_ZONE_DEFAULTS_REFRESH", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_ZONE_DEFAULTS_RETRY") {
            self.dns.zone_defaults.retry =
                parse_env_value("BINDIZR_DNS_ZONE_DEFAULTS_RETRY", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_ZONE_DEFAULTS_EXPIRE") {
            self.dns.zone_defaults.expire =
                parse_env_value("BINDIZR_DNS_ZONE_DEFAULTS_EXPIRE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_ZONE_DEFAULTS_MINIMUM_TTL") {
            self.dns.zone_defaults.minimum_ttl =
                parse_env_value("BINDIZR_DNS_ZONE_DEFAULTS_MINIMUM_TTL", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_LOGGING_LEVEL") {
            self.logging.level = parse_env_value("BINDIZR_LOGGING_LEVEL", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_LOGGING_FORMAT") {
            self.logging.format = parse_env_value("BINDIZR_LOGGING_FORMAT", &value)?;
        }

        Ok(())
    }
}

/// Read an optional setting from an environment override, treating an empty
/// value as unset so containers can leave the variable unfilled.
fn to_optional_setting(value: String) -> Option<String> {
    Some(value.trim().to_string()).filter(|path| !path.is_empty())
}

/// Parse an environment override or return a configuration error.
fn parse_env_value<T>(name: &str, value: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|e| format!("Invalid {} environment variable '{}': {}", name, value, e))
}
