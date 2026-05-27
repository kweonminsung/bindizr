use crate::model::{
    record::{Record, RecordType},
    zone::Zone,
};
use bindizr_core::dns::txt;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Debug, ToSchema)]
pub struct GetZoneResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub primary_ns: String,
    #[schema(example = "admin@example.com")]
    pub admin_email: String,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 2025100101)]
    pub serial: Option<i32>,
    #[schema(example = 7200)]
    pub refresh: i32,
    #[schema(example = 3600)]
    pub retry: i32,
    #[schema(example = 604800)]
    pub expire: i32,
    #[schema(example = 3600)]
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

#[derive(Serialize, Debug, ToSchema)]
pub struct GetRecordResponse {
    #[schema(example = 1)]
    pub id: i32,
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    #[schema(example = "192.168.1.100")]
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = 1)]
    pub zone_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "example.com")]
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

fn record_response_value(record: &Record) -> RecordValueRequest {
    if record.record_type == RecordType::TXT {
        match txt::decode_raw_txt_value(&record.value) {
            Some(txt::DecodedTxtValue::String(value)) => RecordValueRequest::String(value),
            Some(txt::DecodedTxtValue::Segments(segments)) => {
                RecordValueRequest::Segments(segments)
            }
            None => RecordValueRequest::String(record.value.clone()),
        }
    } else {
        RecordValueRequest::String(record.value.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum RecordValueRequest {
    #[schema(example = "192.168.1.100")]
    String(String),
    #[schema(example = json!(["hello", "world"]))]
    Segments(Vec<String>),
}

impl RecordValueRequest {
    pub fn to_storage_value(&self, record_type: &RecordType) -> Result<String, String> {
        match (record_type, self) {
            (RecordType::TXT, RecordValueRequest::String(value)) => {
                Ok(txt::encode_txt_string(value))
            }
            (RecordType::TXT, RecordValueRequest::Segments(segments)) => {
                txt::encode_txt_segments(segments.iter().map(String::as_str))
            }
            (_, RecordValueRequest::String(value)) => Ok(value.clone()),
            (_, RecordValueRequest::Segments(_)) => {
                Err("array value is only supported for TXT records".to_string())
            }
        }
    }
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct CreateZoneRequest {
    #[schema(example = "example.com")]
    pub name: String,
    #[schema(example = "ns1.example.com")]
    pub primary_ns: String,
    #[schema(example = "admin@example.com")]
    pub admin_email: String,
    #[schema(example = 3600)]
    pub ttl: i32,
    #[schema(example = 2025100101)]
    pub serial: Option<i32>, // Optional: auto-generated if not provided
    #[schema(example = 7200)]
    pub refresh: Option<i32>,
    #[schema(example = 3600)]
    pub retry: Option<i32>,
    #[schema(example = 604800)]
    pub expire: Option<i32>,
    #[schema(example = 3600)]
    pub minimum_ttl: Option<i32>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct CreateRecordRequest {
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
    #[schema(example = "example.com")]
    pub zone_name: String,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct UpdateRecordRequest {
    #[schema(example = "sub")]
    pub name: String,
    #[schema(example = "A")]
    pub record_type: String,
    pub value: RecordValueRequest,
    #[schema(example = 3600)]
    pub ttl: Option<i32>,
    #[schema(example = 10)]
    pub priority: Option<i32>,
}

#[derive(Serialize, Debug, ToSchema)]
#[allow(dead_code)]
pub struct ZoneListResponse {
    pub zones: Vec<GetZoneResponse>,
}

#[derive(Serialize, Debug, ToSchema)]
#[allow(dead_code)]
pub struct ZoneDetailResponse {
    pub zone: GetZoneResponse,
    pub records: Vec<GetRecordResponse>,
}

#[derive(Serialize, Debug, ToSchema)]
#[allow(dead_code)]
pub struct ZoneResponse {
    pub zone: GetZoneResponse,
}

#[derive(Serialize, Debug, ToSchema)]
#[allow(dead_code)]
pub struct RecordListResponse {
    pub records: Vec<GetRecordResponse>,
}

#[derive(Serialize, Debug, ToSchema)]
#[allow(dead_code)]
pub struct RecordResponse {
    pub record: GetRecordResponse,
}

#[derive(Serialize, Debug, ToSchema)]
#[allow(dead_code)]
pub struct MessageResponse {
    #[schema(example = "Deleted successfully")]
    pub message: String,
}

#[derive(Serialize, Debug, ToSchema)]
#[allow(dead_code)]
pub struct ErrorResponse {
    #[schema(example = "Bad request: invalid input data")]
    pub error: String,
}
