use crate::database::model::{
    dns::Dns, key::Key, record::Record, record_history::RecordHistory, zone::Zone,
    zone_dns_config::ZoneDnsConfig, zone_history::ZoneHistory,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug)]
pub struct GetZoneResponse {
    pub id: i32,
    pub name: String,
    pub primary_ns: String,
    pub primary_ns_ip: Option<String>,
    pub primary_ns_ipv6: Option<String>,
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
            primary_ns_ipv6: zone.primary_ns_ipv6.clone(),
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
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
    pub zone_id: i32,
}
impl GetRecordResponse {
    pub fn from_record(record: &Record) -> Self {
        GetRecordResponse {
            id: record.id,
            name: record.name.clone(),
            record_type: record.record_type.to_string(),
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
    pub primary_ns_ip: Option<String>,
    pub primary_ns_ipv6: Option<String>,
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
    pub ttl: Option<i32>,
    pub priority: Option<i32>,
    pub zone_name: String,
}

#[derive(Serialize, Debug)]
pub struct GetZoneHistoryResponse {
    pub id: i32,
    pub log: String,
    pub created_at: String,
    pub zone_id: i32,
}
impl GetZoneHistoryResponse {
    pub fn from_zone_history(zone_history: &ZoneHistory) -> Self {
        GetZoneHistoryResponse {
            id: zone_history.id,
            log: zone_history.log.clone(),
            created_at: zone_history.created_at.to_string(),
            zone_id: zone_history.zone_id,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct GetRecordHistoryResponse {
    pub id: i32,
    pub log: String,
    pub created_at: String,
    pub record_id: i32,
}
impl GetRecordHistoryResponse {
    pub fn from_record_history(record_history: &RecordHistory) -> Self {
        GetRecordHistoryResponse {
            id: record_history.id,
            log: record_history.log.clone(),
            created_at: record_history.created_at.to_string(),
            record_id: record_history.record_id,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct GetDnsResponse {
    pub id: i32,
    pub name: String,
    pub host: String,
    pub rndc_port: i32,
    pub created_at: String,
}
impl GetDnsResponse {
    pub fn from_dns(dns: &Dns) -> Self {
        GetDnsResponse {
            id: dns.id,
            name: dns.name.clone(),
            host: dns.host.clone(),
            rndc_port: dns.rndc_port,
            created_at: dns.created_at.to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateDnsRequest {
    pub name: String,
    pub host: String,
    pub rndc_port: i32,
}

#[derive(Deserialize, Debug)]
pub struct UpdateDnsRequest {
    pub name: String,
    pub host: String,
    pub rndc_port: i32,
}

#[derive(Serialize, Debug)]
pub struct GetKeyResponse {
    pub id: i32,
    pub name: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub secret: String,
    pub created_at: String,
}
impl GetKeyResponse {
    pub fn from_key(key: &Key) -> Self {
        GetKeyResponse {
            id: key.id,
            name: key.name.clone(),
            key_type: key.key_type.to_string(),
            key_algorithm: key.key_algorithm.to_string(),
            secret: key.secret.clone(),
            created_at: key.created_at.to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateKeyRequest {
    pub name: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub secret: String,
}

#[derive(Deserialize, Debug)]
pub struct UpdateKeyRequest {
    pub name: String,
    pub key_type: String,
    pub key_algorithm: String,
    pub secret: String,
}

#[derive(Serialize, Debug)]
pub struct GetZoneDnsConfigResponse {
    pub id: i32,
    pub zone_id: i32,
    pub dns_id: i32,
    pub key_id: i32,
    pub created_at: String,
}
impl GetZoneDnsConfigResponse {
    pub fn from_zone_dns_config(zone_dns_config: &ZoneDnsConfig) -> Self {
        GetZoneDnsConfigResponse {
            id: zone_dns_config.id,
            zone_id: zone_dns_config.zone_id,
            dns_id: zone_dns_config.dns_id,
            key_id: zone_dns_config.key_id,
            created_at: zone_dns_config.created_at.to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateZoneDnsConfigRequest {
    pub dns_id: i32,
    pub key_id: i32,
}

#[derive(Deserialize, Debug)]
pub struct UpdateZoneDnsConfigRequest {
    pub dns_id: i32,
    pub key_id: i32,
}

#[derive(Serialize, Debug)]
pub struct GetDnsKeyResponse {
    pub dns_id: i32,
    pub key_id: i32,
    pub dns_name: String,
    pub key_name: String,
    pub created_at: String,
}

impl GetDnsKeyResponse {
    // TODO: This method needs dns_name and key_name from joined data
    pub fn from_dns_key(dns_key: &crate::database::model::dns_key::DnsKey) -> Self {
        GetDnsKeyResponse {
            dns_id: dns_key.dns_id,
            key_id: dns_key.key_id,
            dns_name: "".to_string(), // TODO: fetch from dns table
            key_name: "".to_string(), // TODO: fetch from keys table
            created_at: dns_key.created_at.to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateDnsKeyRequest {
    pub dns_name: String,
    pub key_name: String,
}

#[derive(Deserialize, Debug)]
pub struct UpdateDnsKeyRequest {
    pub key_name: String,
}
