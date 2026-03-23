use serde::Deserialize;
use tabled::Tabled;

// Helper function to display Option<i32> in tables
fn display_option_i32(opt: &Option<i32>) -> String {
    match opt {
        Some(val) => val.to_string(),
        None => "-".to_string(),
    }
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
    #[tabled(rename = "SERIAL", display_with = "display_option_i32")]
    #[serde(default)]
    pub serial: Option<i32>,
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
    #[tabled(rename = "TTL", display_with = "display_option_i32")]
    #[serde(default)]
    pub ttl: Option<i32>,
    #[tabled(rename = "PRIORITY", display_with = "display_option_i32")]
    #[serde(default)]
    pub priority: Option<i32>,
    #[tabled(rename = "ZONE")]
    pub zone_name: String,
}

impl ZoneRow {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("Failed to parse zone: {}", e))
    }
}

impl RecordRow {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("Failed to parse record: {}", e))
    }
}
