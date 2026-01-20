use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct DnsKey {
    pub id: i32,
    pub name: Option<String>,           // optional name for the DNS key
    #[sqlx(try_from = "String")]
    pub key_type: DnsKeyType,           // DNS key type
    #[sqlx(try_from = "String")]
    pub key_algorithm: DnsKeyAlgorithm, // DNS key algorithm
    pub key_name: String,               // key name
    pub secret: String,                 // key secret
    pub created_at: DateTime<Utc>,
    pub dns_instance_id: i32,           // foreign key to dns_instances table
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum DnsKeyType {
    RNDC,
    TSIG,
}
impl std::fmt::Display for DnsKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for DnsKeyType {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        DnsKeyType::from_str(&s)
    }
}
impl DnsKeyType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_uppercase().as_str() {
            "RNDC" => Ok(DnsKeyType::RNDC),
            "TSIG" => Ok(DnsKeyType::TSIG),
            _ => Err(format!("Invalid DNS key type: {}", s)),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            DnsKeyType::RNDC => "RNDC",
            DnsKeyType::TSIG => "TSIG",
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum DnsKeyAlgorithm {
    HMACMD5,
    HMACSHA1,
    HMACSHA224,
    HMACSHA256,
    HMACSHA384,
    HMACSHA512,
}
impl std::fmt::Display for DnsKeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for DnsKeyAlgorithm {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        DnsKeyAlgorithm::from_str(&s)
    }
}
impl DnsKeyAlgorithm {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_uppercase().as_str() {
            "HMACMD5" => Ok(DnsKeyAlgorithm::HMACMD5),
            "HMACSHA1" => Ok(DnsKeyAlgorithm::HMACSHA1),
            "HMACSHA224" => Ok(DnsKeyAlgorithm::HMACSHA224),
            "HMACSHA256" => Ok(DnsKeyAlgorithm::HMACSHA256),
            "HMACSHA384" => Ok(DnsKeyAlgorithm::HMACSHA384),
            "HMACSHA512" => Ok(DnsKeyAlgorithm::HMACSHA512),
            _ => Err(format!("Invalid DNS key algorithm: {}", s)),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            DnsKeyAlgorithm::HMACMD5 => "HMACMD5",
            DnsKeyAlgorithm::HMACSHA1 => "HMACSHA1",
            DnsKeyAlgorithm::HMACSHA224 => "HMACSHA224",
            DnsKeyAlgorithm::HMACSHA256 => "HMACSHA256",
            DnsKeyAlgorithm::HMACSHA384 => "HMACSHA384",
            DnsKeyAlgorithm::HMACSHA512 => "HMACSHA512",
        }
    }
}