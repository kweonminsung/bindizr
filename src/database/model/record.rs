use crate::database::utils;
use chrono::{DateTime, Utc};
use mysql::Value;
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct Record {
    pub id: i32,

    pub name: String, // domain name (ex: "www.example.com")

    pub record_type: RecordType, // record type

    pub value: String, // record value (ex: IP address, CNAME, etc.)

    pub ttl: i32, // TTL (seconds)

    pub priority: Option<i32>, // priority (for MX and SRV records)

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,

    pub zone_id: i32,
}

impl Record {
    pub fn from_row(row: mysql::Row) -> Self {
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

impl RecordType {
    pub fn from_str(s: &str) -> Result<Self, String> {
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

    pub fn to_str(&self) -> &str {
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
