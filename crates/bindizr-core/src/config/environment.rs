//! Environment overrides and their typed parsing, applied before validation.

use std::fmt;

use super::{BindizrConfig, DatabaseType};

impl BindizrConfig {
    /// Apply supported environment variables to the loaded configuration.
    pub(crate) fn apply_env_overrides(
        &mut self,
        get_env: impl Fn(&str) -> Option<String>,
    ) -> Result<(), String> {
        if let Some(value) = get_env("BINDIZR_API_LISTEN_ADDR") {
            self.api.listen_addr = parse_env_value("BINDIZR_API_LISTEN_ADDR", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_PORT") {
            self.api.listen_port = parse_env_value("BINDIZR_API_PORT", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_API_REQUIRE_AUTHENTICATION") {
            self.api.require_authentication =
                parse_env_value("BINDIZR_API_REQUIRE_AUTHENTICATION", &value)?;
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
            self.api.tls_cert_file = to_optional_path(value);
        }
        if let Some(value) = get_env("BINDIZR_API_TLS_KEY_FILE") {
            self.api.tls_key_file = to_optional_path(value);
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_TYPE") {
            self.database.database_type = parse_env_value("BINDIZR_DATABASE_TYPE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_MYSQL_SERVER_URL") {
            self.database.mysql.server_url = value;
        }
        if let Some(value) = get_env("BINDIZR_POSTGRESQL_SERVER_URL") {
            self.database.postgresql.server_url = value;
        }
        if let Some(value) = get_env("BINDIZR_SQLITE_FILE_PATH") {
            self.database.sqlite.file_path = value;
        }
        if let Some(value) = get_env("BINDIZR_DATABASE_URL") {
            match self.database.database_type {
                DatabaseType::Mysql => self.database.mysql.server_url = value,
                DatabaseType::Postgresql => self.database.postgresql.server_url = value,
                DatabaseType::Sqlite => {}
            }
        }
        if let Some(value) = get_env("BINDIZR_DNS_PORT") {
            self.dns.listen_port = parse_env_value("BINDIZR_DNS_PORT", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_DNS_LISTEN_ADDR") {
            self.dns.listen_addr = parse_env_value("BINDIZR_DNS_LISTEN_ADDR", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_SECONDARY_ADDRS") {
            self.dns.secondary_addrs = value;
        }
        if let Some(value) = get_env("BINDIZR_NSUPDATE_ALLOW_UNSIGNED") {
            self.dns.nsupdate_allow_unsigned =
                parse_env_value("BINDIZR_NSUPDATE_ALLOW_UNSIGNED", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_AFTER_UPDATE") {
            self.dns.notify_after_update = parse_env_value("BINDIZR_NOTIFY_AFTER_UPDATE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_MODE") {
            self.dns.notify_mode = parse_env_value("BINDIZR_NOTIFY_MODE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_BATCH_MS") {
            self.dns.notify_batch_ms = parse_env_value("BINDIZR_NOTIFY_BATCH_MS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_CACHE") {
            self.dns.zone_cache = parse_env_value("BINDIZR_ZONE_CACHE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_CACHE_MAX_RECORDS") {
            self.dns.zone_cache_max_records =
                parse_env_value("BINDIZR_ZONE_CACHE_MAX_RECORDS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_ON_STARTUP") {
            self.dns.notify_on_startup = parse_env_value("BINDIZR_NOTIFY_ON_STARTUP", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_RETRIES") {
            self.dns.notify_retries = parse_env_value("BINDIZR_NOTIFY_RETRIES", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_NOTIFY_TIMEOUT_SECS") {
            self.dns.notify_timeout_secs = parse_env_value("BINDIZR_NOTIFY_TIMEOUT_SECS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_JOURNAL_RETENTION_DAYS") {
            self.dns.journal_retention_days =
                parse_env_value("BINDIZR_JOURNAL_RETENTION_DAYS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_MAINTENANCE_INTERVAL_SECS") {
            self.dns.maintenance_interval_secs =
                parse_env_value("BINDIZR_MAINTENANCE_INTERVAL_SECS", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_DEFAULT_TTL") {
            self.dns.zone_defaults.ttl = parse_env_value("BINDIZR_ZONE_DEFAULT_TTL", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_REFRESH") {
            self.dns.zone_defaults.refresh = parse_env_value("BINDIZR_ZONE_REFRESH", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_RETRY") {
            self.dns.zone_defaults.retry = parse_env_value("BINDIZR_ZONE_RETRY", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_EXPIRE") {
            self.dns.zone_defaults.expire = parse_env_value("BINDIZR_ZONE_EXPIRE", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_ZONE_MINIMUM_TTL") {
            self.dns.zone_defaults.minimum_ttl =
                parse_env_value("BINDIZR_ZONE_MINIMUM_TTL", &value)?;
        }
        if let Some(value) = get_env("BINDIZR_LOG_LEVEL") {
            self.logging.log_level = parse_env_value("BINDIZR_LOG_LEVEL", &value)?;
        }

        Ok(())
    }
}

/// Convert an environment path override to an optional path, treating an empty value as unset
/// so containers can leave the variable unfilled.
fn to_optional_path(value: String) -> Option<String> {
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
