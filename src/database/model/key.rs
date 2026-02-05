use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow, Serialize)]
pub struct Key {
    pub id: i32,
    pub name: String, // unique name for the key
    #[sqlx(try_from = "String")]
    pub key_type: KeyType, // key type
    #[sqlx(try_from = "String")]
    pub key_algorithm: KeyAlgorithm, // key algorithm
    pub secret: String, // key secret
    pub created_at: DateTime<Utc>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum KeyType {
    RNDC,
    TSIG,
}
impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for KeyType {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        KeyType::from_str(&s)
    }
}
impl KeyType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_uppercase().as_str() {
            "RNDC" => Ok(KeyType::RNDC),
            "TSIG" => Ok(KeyType::TSIG),
            _ => Err(format!("Invalid key type: {}", s)),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            KeyType::RNDC => "RNDC",
            KeyType::TSIG => "TSIG",
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum KeyAlgorithm {
    HMACMD5,
    HMACSHA1,
    HMACSHA224,
    HMACSHA256,
    HMACSHA384,
    HMACSHA512,
}
impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for KeyAlgorithm {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        KeyAlgorithm::from_str(&s)
    }
}
impl KeyAlgorithm {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_uppercase().as_str() {
            "HMACMD5" => Ok(KeyAlgorithm::HMACMD5),
            "HMACSHA1" => Ok(KeyAlgorithm::HMACSHA1),
            "HMACSHA224" => Ok(KeyAlgorithm::HMACSHA224),
            "HMACSHA256" => Ok(KeyAlgorithm::HMACSHA256),
            "HMACSHA384" => Ok(KeyAlgorithm::HMACSHA384),
            "HMACSHA512" => Ok(KeyAlgorithm::HMACSHA512),
            _ => Err(format!("Invalid key algorithm: {}", s)),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            KeyAlgorithm::HMACMD5 => "HMACMD5",
            KeyAlgorithm::HMACSHA1 => "HMACSHA1",
            KeyAlgorithm::HMACSHA224 => "HMACSHA224",
            KeyAlgorithm::HMACSHA256 => "HMACSHA256",
            KeyAlgorithm::HMACSHA384 => "HMACSHA384",
            KeyAlgorithm::HMACSHA512 => "HMACSHA512",
        }
    }
}
