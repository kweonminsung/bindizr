use crate::{
    database::model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    dns,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Debug)]
pub struct GetZoneResponse {
    pub id: i32,
    pub name: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,
    pub serial: Option<i32>,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum_ttl: i32,
}
impl GetZoneResponse {
    pub fn from_zone(zone: &Zone) -> Self {
        GetZoneResponse {
            id: zone.id,
            name: zone.name.clone(),
            primary_ns: zone.primary_ns.clone(),
            admin_email: zone.admin_email.clone(),
            ttl: zone.ttl,
            serial: Some(zone.serial),
            refresh: zone.refresh,
            retry: zone.retry,
            expire: zone.expire,
            minimum_ttl: zone.minimum_ttl,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct GetRecordResponse {
    pub id: i32,
    pub name: String,
    pub record_type: String,
    pub value: Value,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
    pub zone_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_name: Option<String>,
}
impl GetRecordResponse {
    pub fn from_record(record: &Record) -> Self {
        GetRecordResponse {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.to_string(),
            value: record_response_value(record),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: None,
        }
    }
}

fn record_response_value(record: &Record) -> Value {
    if record.record_type == RecordType::TXT {
        dns::txt::decode_raw_txt_value(&record.value).unwrap_or_else(|| json!(record.value))
    } else {
        json!(record.value)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum RecordValueRequest {
    String(String),
    Segments(Vec<String>),
}

impl RecordValueRequest {
    pub fn to_storage_value(&self, record_type: &RecordType) -> Result<String, String> {
        match (record_type, self) {
            (RecordType::TXT, RecordValueRequest::String(value)) => {
                Ok(dns::txt::encode_txt_string(value))
            }
            (RecordType::TXT, RecordValueRequest::Segments(segments)) => {
                dns::txt::encode_txt_segments(segments.iter().map(String::as_str))
            }
            (_, RecordValueRequest::String(value)) => Ok(value.clone()),
            (_, RecordValueRequest::Segments(_)) => {
                Err("array value is only supported for TXT records".to_string())
            }
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateZoneRequest {
    pub name: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,
    pub serial: Option<i32>, // Optional: auto-generated if not provided
    pub refresh: Option<i32>,
    pub retry: Option<i32>,
    pub expire: Option<i32>,
    pub minimum_ttl: Option<i32>,
}

#[derive(Deserialize, Debug)]
pub struct CreateRecordRequest {
    pub name: String,
    pub record_type: String,
    pub value: RecordValueRequest,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
    pub zone_name: String,
}

#[derive(Deserialize, Debug)]
pub struct UpdateRecordRequest {
    pub name: String,
    pub record_type: String,
    pub value: RecordValueRequest,
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
}
