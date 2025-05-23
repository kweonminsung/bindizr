use crate::database::model::{
    record::Record, record_history::RecordHistory, zone::Zone, zone_history::ZoneHistory,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct GetZoneResponse {
    pub id: i32,
    pub name: String,
    pub primary_ns: String,
    pub primary_ns_ip: String,
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
            primary_ns_ip: zone.primary_ns_ip.clone(),
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
    pub primary_ns_ip: String,
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

#[derive(Serialize, Debug)]
pub struct GetZoneHistoryResponse {
    pub id: i32,
    pub log: String,
    pub created_at: String,
    pub updated_at: String,
    pub zone_id: i32,
}
impl GetZoneHistoryResponse {
    pub fn from_zone_history(zone_history: &ZoneHistory) -> Self {
        GetZoneHistoryResponse {
            id: zone_history.id,
            log: zone_history.log.clone(),
            created_at: zone_history.created_at.to_string(),
            updated_at: zone_history.updated_at.to_string(),
            zone_id: zone_history.zone_id,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct GetRecordHistoryResponse {
    pub id: i32,
    pub log: String,
    pub created_at: String,
    pub updated_at: String,
    pub record_id: i32,
}
impl GetRecordHistoryResponse {
    pub fn from_record_history(record_history: &RecordHistory) -> Self {
        GetRecordHistoryResponse {
            id: record_history.id,
            log: record_history.log.clone(),
            created_at: record_history.created_at.to_string(),
            updated_at: record_history.updated_at.to_string(),
            record_id: record_history.record_id,
        }
    }
}
