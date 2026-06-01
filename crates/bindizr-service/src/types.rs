use crate::model::{
    record::{Record, RecordType, RecordWithZone},
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
            value: record_response_value(record, false),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: None,
        }
    }

    pub fn from_record_and_zone_name(record: &Record, zone_name: &str) -> Self {
        GetRecordResponse {
            id: record.id,
            name: display_record_owner_name(&record.name, zone_name),
            record_type: record.record_type.to_string(),
            value: record_response_value(record, true),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
            zone_name: Some(display_zone_name(zone_name)),
        }
    }

    pub fn from_record_with_zone(record: &RecordWithZone) -> Self {
        Self::from_record_and_zone_name(&record.record(), &record.zone_name)
    }
}

fn record_response_value(record: &Record, display_names: bool) -> RecordValueRequest {
    if record.record_type == RecordType::TXT {
        match txt::decode_raw_txt_value(&record.value) {
            Some(txt::DecodedTxtValue::String(value)) => RecordValueRequest::String(value),
            Some(txt::DecodedTxtValue::Segments(segments)) => {
                RecordValueRequest::Segments(segments)
            }
            None => RecordValueRequest::String(record.value.clone()),
        }
    } else if display_names {
        RecordValueRequest::String(display_record_value(&record.value, &record.record_type))
    } else {
        RecordValueRequest::String(record.value.clone())
    }
}

fn display_record_owner_name(stored_name: &str, zone_name: &str) -> String {
    let zone_fqdn = display_zone_name(zone_name);
    let trimmed = stored_name.trim();

    if trimmed == "@" {
        return zone_fqdn;
    }

    if trimmed.ends_with('.') {
        return display_zone_name(trimmed);
    }

    let candidate = display_zone_name(trimmed);
    if candidate == zone_fqdn || candidate.ends_with(&format!(".{}", zone_fqdn)) {
        candidate
    } else {
        display_zone_name(&format!("{}.{}", trimmed, zone_fqdn))
    }
}

fn display_zone_name(zone_name: &str) -> String {
    format!(
        "{}.",
        zone_name.trim().trim_end_matches('.').to_ascii_lowercase()
    )
}

fn display_record_value(value: &str, record_type: &RecordType) -> String {
    match record_type {
        RecordType::CNAME | RecordType::NS | RecordType::PTR => display_zone_name(value),
        RecordType::MX | RecordType::SRV => display_last_name_field(value),
        _ => value.to_string(),
    }
}

fn display_last_name_field(value: &str) -> String {
    let mut fields = value
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let Some(last) = fields.pop() else {
        return value.to_string();
    };

    fields.push(display_zone_name(&last));
    fields.join(" ")
}

#[cfg(test)]
mod tests {
    use super::{display_record_owner_name, display_record_value};
    use crate::model::record::RecordType;

    #[test]
    fn display_record_owner_name_returns_absolute_fqdn() {
        let zone = "test.example.com";

        assert_eq!(display_record_owner_name("@", zone), "test.example.com.");
        assert_eq!(
            display_record_owner_name("a1", zone),
            "a1.test.example.com."
        );
        assert_eq!(
            display_record_owner_name("_acme-challenge", zone),
            "_acme-challenge.test.example.com."
        );
        assert_eq!(
            display_record_owner_name("a1.test.example.com.", zone),
            "a1.test.example.com."
        );
    }

    #[test]
    fn display_record_value_adds_trailing_dot_for_name_like_values() {
        assert_eq!(
            display_record_value("ns.test.example.com", &RecordType::NS),
            "ns.test.example.com."
        );
        assert_eq!(
            display_record_value("Target.Example.Net", &RecordType::CNAME),
            "target.example.net."
        );
        assert_eq!(
            display_record_value("10 mail.example.com", &RecordType::MX),
            "10 mail.example.com."
        );
        assert_eq!(
            display_record_value("10 5 5060 sip.example.com", &RecordType::SRV),
            "10 5 5060 sip.example.com."
        );
        assert_eq!(
            display_record_value("host.example.com", &RecordType::PTR),
            "host.example.com."
        );
    }

    #[test]
    fn display_record_value_keeps_non_name_values_unchanged() {
        assert_eq!(
            display_record_value("127.0.0.1", &RecordType::A),
            "127.0.0.1"
        );
        assert_eq!(
            display_record_value("2001:db8::1", &RecordType::AAAA),
            "2001:db8::1"
        );
        assert_eq!(
            display_record_value("v=spf1 include:example.net", &RecordType::TXT),
            "v=spf1 include:example.net"
        );
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
