use chrono::{DateTime, Utc};
use sqlx::FromRow;

/// TSIG HMAC algorithms supported for nsupdate authentication (RFC 8945).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TsigAlgorithm {
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

    /// All supported algorithm names, for error messages and CLI help.
    pub(crate) fn supported_names() -> &'static [&'static str] {
        &["hmac-sha256", "hmac-sha384", "hmac-sha512"]
    }
}

impl std::fmt::Display for TsigAlgorithm {
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
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A TSIG key used to authenticate nsupdate requests. Keys are standalone
/// credentials granted to zones through
/// [`super::zone_tsig_policy::ZoneTsigPolicy`] rows; `name` is the wire name.
///
/// `is_global` is fixed at creation: a global key may update every zone
/// (all names, all types) without any policy.
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
