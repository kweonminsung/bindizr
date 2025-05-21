use crate::database::model::{record::Record, zone::Zone};
use serde::{Deserialize, Serialize};

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
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub zone_id: i32,
}
impl GetRecordResponse {
    pub fn from_record(record: &Record) -> Self {
        GetRecordResponse {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.to_str().to_string(),
            value: record.value.clone(),
            ttl: record.ttl,
            priority: record.priority,
            zone_id: record.zone_id,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateZoneRequest {
    pub name: String,
    pub primary_ns: String,
    pub admin_email: String,
    pub ttl: i32,
    pub serial: i32,
    pub refresh: Option<i32>,
    pub retry: Option<i32>,
    pub expire: Option<i32>,
    pub minimum_ttl: Option<i32>,
}

#[derive(Deserialize, Debug)]
pub struct CreateRecordRequest {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
    pub zone_id: i32,
}
