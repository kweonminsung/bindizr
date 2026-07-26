use serde::Deserialize;
use tabled::Tabled;

// Display Option<i32> in tables, using "-" for None.
fn display_option_i32(opt: &Option<i32>) -> String {
    match opt {
        Some(val) => val.to_string(),
        None => "-".to_string(),
    }
}

// Deserialize a record value, which may be a string or an array of strings.
fn deserialize_record_value<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(value) => value,
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                serde_json::Value::String(value) => value,
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join(""),
        other => other.to_string(),
    })
}

/// Table row for zone display.
#[derive(Debug, Deserialize, Tabled)]
pub(crate) struct ZoneRow {
    #[tabled(rename = "ID")]
    pub id: i32,
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "PRIMARY-NS")]
    pub primary_ns: String,
    #[tabled(rename = "ADMIN-EMAIL")]
    pub admin_email: String,
    #[tabled(rename = "TTL")]
    pub ttl: i32,
    #[tabled(rename = "SERIAL", display = "display_option_i32")]
    #[serde(default)]
    pub serial: Option<i32>,
}

/// Table row for record display.
#[derive(Debug, Deserialize, Tabled)]
pub(crate) struct RecordRow {
    #[tabled(rename = "ID")]
    pub id: i32,
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "TYPE")]
    pub record_type: String,
    #[tabled(rename = "VALUE")]
    #[serde(deserialize_with = "deserialize_record_value")]
    pub value: String,
    #[tabled(rename = "TTL", display = "display_option_i32")]
    #[serde(default)]
    pub ttl: Option<i32>,
    #[tabled(rename = "PRIORITY", display = "display_option_i32")]
    #[serde(default)]
    pub priority: Option<i32>,
    #[tabled(rename = "ZONE")]
    pub zone_name: String,
}

/// Table row for zone snapshot display.
#[derive(Debug, Deserialize, Tabled)]
pub(crate) struct SnapshotRow {
    #[tabled(rename = "SERIAL")]
    pub serial: i32,
    #[tabled(rename = "PRIMARY-NS")]
    pub primary_ns: String,
    #[tabled(rename = "ADMIN-EMAIL")]
    pub admin_email: String,
    #[tabled(rename = "TTL")]
    pub ttl: i32,
    #[tabled(rename = "CREATED-AT")]
    pub created_at: String,
}

impl SnapshotRow {
    /// Build a [`SnapshotRow`] from a JSON value.
    pub(crate) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone())
            .map_err(|e| format!("Failed to parse snapshot: {}", e))
    }
}

/// Table row for records reconstructed at a snapshot serial (no database id).
#[derive(Debug, Deserialize, Tabled)]
pub(crate) struct SnapshotRecordRow {
    #[tabled(rename = "NAME")]
    pub name: String,
    #[tabled(rename = "TYPE")]
    pub record_type: String,
    #[tabled(rename = "VALUE")]
    #[serde(deserialize_with = "deserialize_record_value")]
    pub value: String,
    #[tabled(rename = "TTL", display = "display_option_i32")]
    #[serde(default)]
    pub ttl: Option<i32>,
    #[tabled(rename = "PRIORITY", display = "display_option_i32")]
    #[serde(default)]
    pub priority: Option<i32>,
}

impl SnapshotRecordRow {
    /// Build a [`SnapshotRecordRow`] from a JSON value.
    pub(crate) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("Failed to parse record: {}", e))
    }
}

/// Table row for rollback result summaries.
#[derive(Debug, Deserialize, Tabled)]
pub(crate) struct RollbackSummaryRow {
    #[tabled(rename = "TARGET-SERIAL")]
    pub target_serial: i32,
    #[tabled(rename = "NEW-SERIAL")]
    pub new_serial: i32,
    #[tabled(rename = "APPLIED")]
    pub applied: bool,
    #[tabled(rename = "ADDED")]
    pub records_added: usize,
    #[tabled(rename = "DELETED")]
    pub records_deleted: usize,
    #[tabled(rename = "UNCHANGED")]
    pub records_unchanged: usize,
    #[tabled(rename = "SOA-CHANGED")]
    pub soa_changed: bool,
}

impl RollbackSummaryRow {
    /// Build a [`RollbackSummaryRow`] from a JSON value, flattening the summary.
    pub(crate) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let mut flattened = value.clone();
        if let (Some(object), Some(summary)) = (
            flattened.as_object_mut(),
            value.get("summary").and_then(|v| v.as_object()).cloned(),
        ) {
            for (key, entry) in summary {
                object.insert(key, entry);
            }
        }
        serde_json::from_value(flattened)
            .map_err(|e| format!("Failed to parse rollback result: {}", e))
    }
}

/// Table row for per-secondary zone sync status.
#[derive(Debug, Tabled)]
pub(crate) struct SecondaryStatusRow {
    #[tabled(rename = "ADDRESS")]
    pub address: String,
    #[tabled(rename = "STATUS")]
    pub status: String,
    #[tabled(rename = "VISIBLE-SERIAL")]
    pub visible_serial: String,
    #[tabled(rename = "LAG")]
    pub lag: String,
}

impl SecondaryStatusRow {
    /// Build rows from a `ZoneStatusResponse` JSON payload, deriving each
    /// secondary's lag from the zone serial.
    pub(crate) fn rows_from_status(data: &serde_json::Value) -> Result<Vec<Self>, String> {
        let serial = data
            .get("serial")
            .and_then(|v| v.as_i64())
            .ok_or("Missing serial in response")?;
        let secondaries = data
            .get("secondaries")
            .and_then(|v| v.as_array())
            .ok_or("Missing secondaries in response")?;

        Ok(secondaries
            .iter()
            .map(|entry| {
                let visible = entry.get("visible_serial").and_then(|v| v.as_i64());
                let status = entry
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let detail = match (status, entry.get("error").and_then(|v| v.as_str())) {
                    ("unreachable", Some(error)) => format!("unreachable ({})", error),
                    _ => status.to_string(),
                };
                SecondaryStatusRow {
                    address: entry
                        .get("address")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    status: detail,
                    visible_serial: visible.map_or_else(|| "-".to_string(), |v| v.to_string()),
                    lag: visible.map_or_else(|| "-".to_string(), |v| (serial - v).to_string()),
                }
            })
            .collect())
    }
}

/// Table row for zone-file import summaries.
#[derive(Debug, Deserialize, Tabled)]
pub(crate) struct ImportSummaryRow {
    #[tabled(rename = "PARSED")]
    pub parsed: usize,
    #[tabled(rename = "ADDED")]
    pub added: usize,
    #[tabled(rename = "DELETED")]
    pub deleted: usize,
    #[tabled(rename = "UPDATED")]
    pub updated: usize,
    #[tabled(rename = "UNCHANGED")]
    pub unchanged: usize,
    #[tabled(rename = "SKIPPED")]
    pub skipped: usize,
}

impl ImportSummaryRow {
    /// Build an [`ImportSummaryRow`] from a JSON value.
    pub(crate) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone())
            .map_err(|e| format!("Failed to parse import summary: {}", e))
    }
}

impl ZoneRow {
    /// Build a [`ZoneRow`] from a JSON value.
    pub(crate) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("Failed to parse zone: {}", e))
    }
}

impl RecordRow {
    /// Build a [`RecordRow`] from a JSON value.
    pub(crate) fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("Failed to parse record: {}", e))
    }
}
