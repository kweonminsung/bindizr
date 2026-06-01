use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct Record {
    pub id: i32,
    pub name: String, // domain name (e.g.: "www.example.com")
    #[sqlx(try_from = "String")]
    pub record_type: RecordType, // record type
    pub value: String, // record value (e.g.: IP address, CNAME, etc.)
    pub ttl: Option<i32>, // TTL (seconds)
    pub priority: Option<i32>, // priority (for MX and SRV records)
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
}

#[derive(Debug, PartialEq, Eq, Clone, FromRow)]
pub struct RecordWithZone {
    pub id: i32,
    pub name: String,
    #[sqlx(try_from = "String")]
    pub record_type: RecordType,
    pub value: String,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub zone_id: i32,
    pub zone_name: String,
}

impl RecordWithZone {
    pub fn new(record: Record, zone_name: String) -> Self {
        Self {
            id: record.id,
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
            created_at: record.created_at,
            zone_id: record.zone_id,
            zone_name,
        }
    }

    pub fn record(&self) -> Record {
        Record {
            id: self.id,
            name: self.name.clone(),
            record_type: self.record_type.clone(),
            value: self.value.clone(),
            ttl: self.ttl,
            priority: self.priority,
            created_at: self.created_at,
            zone_id: self.zone_id,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    SRV,
    PTR,
}
impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl TryFrom<String> for RecordType {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl std::str::FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "NS" => Ok(RecordType::NS),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "PTR" => Ok(RecordType::PTR),
            _ => Err(format!("Invalid record type: {}", s)),
        }
    }
}

impl RecordType {
    pub fn as_str(&self) -> &str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::NS => "NS",
            RecordType::SOA => "SOA",
            RecordType::SRV => "SRV",
            RecordType::PTR => "PTR",
        }
    }
}
