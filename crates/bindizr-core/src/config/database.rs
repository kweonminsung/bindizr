//! Database backend, connection location, and TLS policy.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, ParseConfigValueError};

/// Database backend selection and per-backend connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    #[serde(default, rename = "type")]
    pub database_type: DatabaseType,
    #[serde(default)]
    pub mysql: MySqlConfig,
    #[serde(default)]
    pub sqlite: SqliteConfig,
    #[serde(default)]
    pub postgresql: PostgresConfig,
    #[serde(default)]
    pub tls: DatabaseTlsConfig,
}

impl DatabaseConfig {
    /// Validate the database configuration fields.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        self.tls.validate()?;

        match self.database_type {
            DatabaseType::MySql if self.mysql.url.trim().is_empty() => {
                Err(ConfigError::EmptyDatabaseLocation {
                    key: "database.mysql.url",
                    database_type: DatabaseType::MySql,
                })
            }
            DatabaseType::Postgres if self.postgresql.url.trim().is_empty() => {
                Err(ConfigError::EmptyDatabaseLocation {
                    key: "database.postgresql.url",
                    database_type: DatabaseType::Postgres,
                })
            }
            DatabaseType::Sqlite if self.sqlite.file_path.trim().is_empty() => {
                Err(ConfigError::EmptyDatabaseLocation {
                    key: "database.sqlite.file_path",
                    database_type: DatabaseType::Sqlite,
                })
            }
            _ => Ok(()),
        }
    }
}

/// Supported database backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DatabaseType {
    MySql,
    #[default]
    Sqlite,
    #[serde(rename = "postgresql")]
    Postgres,
}

impl DatabaseType {
    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgresql",
        }
    }
}

impl fmt::Display for DatabaseType {
    /// Write the database type in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DatabaseType {
    type Err = ParseConfigValueError;

    /// Parse a database type from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mysql" => Ok(Self::MySql),
            "sqlite" => Ok(Self::Sqlite),
            "postgresql" => Ok(Self::Postgres),
            _ => Err(ParseConfigValueError {
                expected: "mysql, postgresql, or sqlite",
            }),
        }
    }
}

/// MySQL connection settings.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MySqlConfig {
    pub url: String,
}

impl fmt::Debug for MySqlConfig {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MySqlConfig")
            .field("url", &"<redacted>")
            .finish()
    }
}

/// SQLite connection settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqliteConfig {
    pub file_path: String,
}

/// PostgreSQL connection settings.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    pub url: String,
}

impl fmt::Debug for PostgresConfig {
    /// Format the diagnostic fields with credential material redacted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresConfig")
            .field("url", &"<redacted>")
            .finish()
    }
}

/// TLS to the MySQL or PostgreSQL server. A set key overrides the URL's own
/// parameter; unset leaves the URL and sqlx's default (TLS if offered, unverified).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseTlsConfig {
    #[serde(default)]
    pub mode: Option<DatabaseTlsMode>,
    /// A private issuer to check the server's certificate against; the
    /// system roots otherwise.
    #[serde(default)]
    pub ca_file: Option<String>,
}

impl DatabaseTlsConfig {
    /// Validate the TLS fields.
    fn validate(&self) -> Result<(), ConfigError> {
        // A CA that no mode consults would read as protection it is not.
        if self.ca_file.is_some()
            && !matches!(
                self.mode,
                Some(DatabaseTlsMode::VerifyCa | DatabaseTlsMode::VerifyFull)
            )
        {
            return Err(ConfigError::DatabaseTlsCaUnchecked);
        }

        Ok(())
    }
}

/// How far the database connection insists on TLS, in PostgreSQL's words;
/// MySQL's modes map one to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DatabaseTlsMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl DatabaseTlsMode {
    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Prefer => "prefer",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }
}

impl fmt::Display for DatabaseTlsMode {
    /// Write the mode in its configuration spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DatabaseTlsMode {
    type Err = ParseConfigValueError;

    /// Parse a TLS mode from its configuration spelling.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disable" => Ok(Self::Disable),
            "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-full" => Ok(Self::VerifyFull),
            _ => Err(ParseConfigValueError {
                expected: "disable, prefer, require, verify-ca, or verify-full",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that database credentials stay out of direct and nested Debug output.
    #[test]
    fn database_urls_mask_credentials_in_debug() {
        let config: DatabaseConfig = serde_json::from_value(json!({
            "mysql": {"url": "mysql://example:fixture-password@db.example/zone"},
            "postgresql": {"url": "postgresql://example:fixture-password@db.example/zone"}
        }))
        .unwrap();
        for debug in [
            format!("{:?}", config.mysql),
            format!("{:#?}", config.postgresql),
            format!("{config:#?}"),
        ] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("fixture-password"));
        }
        assert_eq!(
            serde_json::to_value(&config).unwrap()["mysql"]["url"],
            config.mysql.url
        );
    }
}
