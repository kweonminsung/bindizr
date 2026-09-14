use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// TSIG HMAC algorithms for update and transfer authentication (RFC 8945).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum TsigAlgorithm {
    /// The default a key is created with, matching `tsig-keygen`'s.
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    /// Presentation/storage name, identical to the wire algorithm name without
    /// the trailing root dot (e.g. `"hmac-sha256"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            TsigAlgorithm::HmacSha256 => "hmac-sha256",
            TsigAlgorithm::HmacSha384 => "hmac-sha384",
            TsigAlgorithm::HmacSha512 => "hmac-sha512",
        }
    }

    /// All supported algorithm names, for error messages.
    pub(crate) fn supported_names() -> &'static [&'static str] {
        &["hmac-sha256", "hmac-sha384", "hmac-sha512"]
    }
}

impl std::fmt::Display for TsigAlgorithm {
    /// Write the TSIG algorithm in its display form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TsigAlgorithm {
    type Err = String;

    /// Accepts the storage form or the wire form (trailing root dot tolerated),
    /// case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim_end_matches('.').to_ascii_lowercase().as_str() {
            "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
            "hmac-sha384" => Ok(TsigAlgorithm::HmacSha384),
            "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
            _ => Err(format!(
                "unsupported TSIG algorithm '{}' (supported: {})",
                s,
                TsigAlgorithm::supported_names().join(", ")
            )),
        }
    }
}

impl TryFrom<String> for TsigAlgorithm {
    type Error = String;

    /// Validate and convert the stored value into a TSIG algorithm.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A TSIG credential for updates and transfers; `name` is its wire name.
/// Zone rights come from [`super::tsig_grant::TsigGrant`] rows.
///
/// `is_global` is fixed at creation: a global key may update and transfer
/// every zone without any grant.
#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct TsigKey {
    pub id: i32,
    pub name: String,
    #[sqlx(try_from = "String")]
    pub algorithm: TsigAlgorithm,
    pub secret: String,
    pub is_global: bool,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
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
}
