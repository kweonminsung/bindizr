use crate::database::model::{
    record::Record, record_history::RecordHistory, zone::Zone, zone_history::ZoneHistory,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub(crate) struct GetZoneResponse {
    pub(crate) id: i32,
    pub(crate) name: String,
    pub(crate) primary_ns: String,
    pub(crate) primary_ns_ip: String,
    pub(crate) admin_email: String,
    pub(crate) ttl: i32,
    pub(crate) serial: Option<i32>,
    pub(crate) refresh: i32,
    pub(crate) retry: i32,
    pub(crate) expire: i32,
    pub(crate) minimum_ttl: i32,
}
impl GetZoneResponse {
    pub(crate) fn from_zone(zone: &Zone) -> Self {
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
pub(crate) struct GetRecordResponse {
    pub(crate) id: i32,
    pub(crate) name: String,
    pub(crate) record_type: String,
    pub(crate) value: String,
    pub(crate) ttl: i32,
    pub(crate) priority: Option<i32>,
    pub(crate) zone_id: i32,
}
impl GetRecordResponse {
    pub(crate) fn from_record(record: &Record) -> Self {
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
pub(crate) struct CreateZoneRequest {
    pub(crate) name: String,
    pub(crate) primary_ns: String,
    pub(crate) primary_ns_ip: String,
    pub(crate) admin_email: String,
    pub(crate) ttl: i32,
    pub(crate) serial: i32,
    pub(crate) refresh: Option<i32>,
    pub(crate) retry: Option<i32>,
    pub(crate) expire: Option<i32>,
    pub(crate) minimum_ttl: Option<i32>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct CreateRecordRequest {
    pub(crate) name: String,
    pub(crate) record_type: String,
    pub(crate) value: String,
    pub(crate) ttl: i32,
    pub(crate) priority: Option<i32>,
    pub(crate) zone_id: i32,
}

#[derive(Serialize, Debug)]
pub(crate) struct GetZoneHistoryResponse {
    pub(crate) id: i32,
    pub(crate) log: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) zone_id: i32,
}
impl GetZoneHistoryResponse {
    pub(crate) fn from_zone_history(zone_history: &ZoneHistory) -> Self {
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
pub(crate) struct GetRecordHistoryResponse {
    pub(crate) id: i32,
    pub(crate) log: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) record_id: i32,
}
impl GetRecordHistoryResponse {
    pub(crate) fn from_record_history(record_history: &RecordHistory) -> Self {
        GetRecordHistoryResponse {
            id: record_history.id,
            log: record_history.log.clone(),
            created_at: record_history.created_at.to_string(),
            updated_at: record_history.updated_at.to_string(),
            record_id: record_history.record_id,
        }
    }
}
