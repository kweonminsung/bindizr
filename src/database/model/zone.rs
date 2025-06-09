use crate::database::utils;
use chrono::{DateTime, Utc};
use mysql::Value;

// structure for basic creation of SOA records and basic creation of NS records
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Zone {
    pub id: i32,

    pub name: String, // zone name (e.g.: "example.com")

    pub primary_ns: String, // primary name server (e.g.: "ns1.example.com")

    pub primary_ns_ip: String, // primary name server IP

    pub admin_email: String, // admin email (e.g.: "admin.example.com")

    pub ttl: i32, // default TTL (seconds)

    pub serial: i32, // serial number (SOA record)

    pub refresh: i32, // refresh period (seconds)

    pub retry: i32, // retry period (seconds)

    pub expire: i32, // expire period (seconds)

    pub minimum_ttl: i32, // minimum TTL (seconds)

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,
}

impl Zone {
    pub fn from_row(row: mysql::Row) -> Self {
        Zone {
            id: row.get("id").unwrap(),
            name: row.get("name").unwrap(),
            primary_ns: row.get("primary_ns").unwrap(),
            primary_ns_ip: row.get("primary_ns_ip").unwrap(),
            admin_email: row.get("admin_email").unwrap(),
            ttl: row.get("ttl").unwrap(),
            serial: row.get("serial").unwrap(),
            refresh: row.get("refresh").unwrap(),
            retry: row.get("retry").unwrap(),
            expire: row.get("expire").unwrap(),
            minimum_ttl: row.get("minimum_ttl").unwrap(),
            created_at: utils::parse_mysql_datetime(&row.get::<Value, _>("created_at").unwrap()),
            updated_at: utils::parse_mysql_datetime(&row.get::<Value, _>("updated_at").unwrap()),
        }
    }
}
