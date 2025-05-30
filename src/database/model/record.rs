use crate::database::utils;
use chrono::{DateTime, Utc};
use mysql::Value;
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Record {
    pub(crate) id: i32,

    pub(crate) name: String, // domain name (e.g.: "www.example.com")

    pub(crate) record_type: RecordType, // record type

    pub(crate) value: String, // record value (e.g.: IP address, CNAME, etc.)

    pub(crate) ttl: Option<i32>, // TTL (seconds)

    pub(crate) priority: Option<i32>, // priority (for MX and SRV records)

    pub(crate) created_at: DateTime<Utc>,

    pub(crate) updated_at: DateTime<Utc>,

    pub(crate) zone_id: i32,
}

impl Record {
    pub(crate) fn from_row(row: mysql::Row) -> Self {
        Record {
            id: row.get("id").unwrap(),
            name: row.get("name").unwrap(),
            record_type: RecordType::from_str(&row.get::<String, _>("record_type").unwrap())
                .unwrap(),
            value: row.get("value").unwrap(),
            ttl: row.get("ttl").unwrap(),
            priority: row.get("priority").unwrap(),
            created_at: utils::parse_mysql_datetime(&row.get::<Value, _>("created_at").unwrap()),
            updated_at: utils::parse_mysql_datetime(&row.get::<Value, _>("updated_at").unwrap()),
            zone_id: row.get("zone_id").unwrap(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub(crate) enum RecordType {
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
        write!(f, "{}", self.to_str())
    }
}

impl RecordType {
    pub(crate) fn from_str(s: &str) -> Result<Self, String> {
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

    pub(crate) fn to_str(&self) -> &str {
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
