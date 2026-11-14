use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;
use utoipa::ToSchema;

use crate::model::role::RoleId;

/// A TSIG algorithm name outside the HMACs bindizr signs with.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported TSIG algorithm '{value}' (supported: {})", TsigAlgorithm::supported_names().join(", "))]
pub struct ParseTsigAlgorithmError {
    pub value: String,
}

/// TSIG HMAC algorithms for update and transfer authentication (RFC 8945).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    /// Required for interoperability by RFC 8945, Section 6; prefer SHA256.
    HmacSha1,
    /// The default a key is created with, matching `tsig-keygen`'s.
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    /// Return the canonical wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        }
    }

    /// Return the HMAC output length in bytes, the least a secret should hold
    /// (RFC 8945, Section 8).
    pub fn digest_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }

    /// List all supported algorithm names, for error messages.
    fn supported_names() -> &'static [&'static str] {
        &["hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"]
    }
}

impl fmt::Display for TsigAlgorithm {
    /// Write the TSIG algorithm in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TsigAlgorithm {
    type Err = ParseTsigAlgorithmError;

    /// Accept the storage form or the wire form (trailing root dot tolerated),
    /// case-insensitively.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim_end_matches('.').to_ascii_lowercase().as_str() {
            "hmac-sha1" => Ok(Self::HmacSha1),
            "hmac-sha256" => Ok(Self::HmacSha256),
            "hmac-sha384" => Ok(Self::HmacSha384),
            "hmac-sha512" => Ok(Self::HmacSha512),
            _ => Err(ParseTsigAlgorithmError {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for TsigAlgorithm {
    type Error = ParseTsigAlgorithmError;

    /// Validate and convert the stored value into a TSIG algorithm.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

id_newtype!(
    /// The id of a TSIG key row.
    TsigKeyId
);

/// A TSIG credential whose wire `name` identifies it for updates and transfers.
/// Rights come from its role's [`crate::model::role_grant::RoleGrant`] rows; a key
/// that only signs outbound NOTIFY names a role with none.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TsigKey {
    pub id: TsigKeyId,
    pub name: String,
    #[sqlx(try_from = "String")]
    pub algorithm: TsigAlgorithm,
    pub secret: String,
    pub role_id: RoleId,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that algorithm parses storage and wire forms case insensitively.
    #[test]
    fn algorithm_parses_storage_and_wire_forms_case_insensitively() {
        assert_eq!(
            "HMAC-SHA512".parse::<TsigAlgorithm>().unwrap(),
            TsigAlgorithm::HmacSha512
        );
        assert_eq!(
            "hmac-sha384.".parse::<TsigAlgorithm>().unwrap(),
            TsigAlgorithm::HmacSha384
        );
    }

    /// Verify that algorithm rejects unsupported names.
    #[test]
    fn algorithm_rejects_unsupported_names() {
        assert!("hmac-md5".parse::<TsigAlgorithm>().is_err());
    }

    /// Verify that `TsigAlgorithm` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn tsig_algorithm_spells_itself_once() {
        for value in [
            TsigAlgorithm::HmacSha1,
            TsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512,
        ] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<TsigAlgorithm>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<TsigAlgorithm>().unwrap(), value);
        }
    }
}
