use serde::Deserialize;
use tabled::Tabled;

/// Table row for DNS instance display
#[derive(Debug, Deserialize, Tabled)]
pub struct DnsInstanceRow {
    // #[tabled(rename = "ID")]
    // pub id: i32,
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "HOST")]
    pub host: String,
    #[tabled(rename = "RNDC-PORT")]
    pub rndc_port: i32,
    #[tabled(rename = "RNDC-KEY-ID")]
    pub rndc_key_id: i32,
}

/// Table row for DNS key display
#[derive(Debug, Deserialize, Tabled)]
pub struct DnsKeyRow {
    // #[tabled(rename = "ID")]
    // pub id: i32,
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "TYPE")]
    pub key_type: String,
    #[tabled(rename = "ALGORITHM")]
    pub key_algorithm: String,
    #[tabled(rename = "KEY-NAME")]
    pub key_name: String,
}

/// Table row for zone display
#[derive(Debug, Deserialize, Tabled)]
pub struct ZoneRow {
    // #[tabled(rename = "ID")]
    // pub id: i32,
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "PRIMARY-NS")]
    pub primary_ns: String,
    #[tabled(rename = "ADMIN-EMAIL")]
    pub admin_email: String,
    #[tabled(rename = "TTL")]
    pub ttl: i32,
    #[tabled(rename = "SERIAL")]
    pub serial: i32,
}

/// Table row for record display
#[derive(Debug, Deserialize, Tabled)]
pub struct RecordRow {
    // #[tabled(rename = "ID")]
    // pub id: i32,
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "TYPE")]
    pub record_type: String,
    #[tabled(rename = "VALUE")]
    pub value: String,
    #[tabled(rename = "TTL")]
    pub ttl: String,
    #[tabled(rename = "PRIORITY")]
    pub priority: String,
    #[tabled(rename = "ZONE-ID")]
    pub zone_id: i32,
}

impl DnsInstanceRow {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone())
            .map(|mut row: Self| {
                if row.name.is_empty() {
                    row.name = "-".to_string();
                }
                row
            })
            .map_err(|e| format!("Failed to parse DNS instance: {}", e))
    }
}

impl DnsKeyRow {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone())
            .map(|mut row: Self| {
                if row.name.is_empty() {
                    row.name = "-".to_string();
                }
                row
            })
            .map_err(|e| format!("Failed to parse DNS key: {}", e))
    }
}

impl ZoneRow {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("Failed to parse zone: {}", e))
    }
}

impl RecordRow {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone())
            .map(|mut row: Self| {
                if row.ttl.is_empty() {
                    row.ttl = "-".to_string();
                }
                if row.priority.is_empty() {
                    row.priority = "-".to_string();
                }
                row
            })
            .map_err(|e| format!("Failed to parse record: {}", e))
    }
}
