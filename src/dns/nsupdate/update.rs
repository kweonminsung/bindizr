use super::parser::{UpdateRecord, UpdateRequest, decode_name_from_rdata, decode_txt_from_rdata};
use crate::{
    database::model::{
        record::{Record, RecordType},
        zone::Zone,
        zone_change::ZoneChange,
        zone_snapshot::ZoneSnapshot,
    },
    dns, log_error, log_info,
    service::record::{find_identical_record_in_zone, validate_nsupdate_add_constraints},
    service::repository::RepositoryService,
};
use chrono::Utc;
use std::net::SocketAddr;

pub(super) const CLASS_IN: u16 = 1;
pub(super) const CLASS_NONE: u16 = 254;
pub(super) const CLASS_ANY: u16 = 255;

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
pub(super) const TYPE_ANY: u16 = 255;

#[derive(Debug)]
pub enum UpdateError {
    Refused(String),
    YxDomain(String),
    YxRrset(String),
    NxDomain(String),
    NxRrset(String),
    NotZone(String),
    Internal(String),
}

pub enum UpdateResult {
    Applied { changed: bool },
}

pub async fn apply_update(
    request: UpdateRequest,
    query_data: &[u8],
    client_addr: SocketAddr,
) -> Result<UpdateResult, UpdateError> {
    super::auth::validate_tsig(&request, query_data, client_addr)?;

    let zone_name = trim_dot(&request.zone_name);
    if zone_name.is_empty() {
        return Err(UpdateError::NotZone(
            "root zone is not supported".to_string(),
        ));
    }

    let zone = RepositoryService::get_zone_by_name(zone_name)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to load zone: {}", e)))?
        .ok_or_else(|| UpdateError::NotZone(format!("zone '{}' not found", zone_name)))?;

    super::prerequisite::evaluate_prerequisites(&zone, &request.prerequisites, query_data).await?;

    let mut changed = false;

    for update in &request.updates {
        let this_changed = apply_single_update(&zone, update, query_data).await?;
        changed = changed || this_changed;
    }

    if changed {
        let new_serial = bump_zone_serial(&zone).await?;
        save_zone_snapshot(&zone, new_serial).await?;

        if let Err(e) = dns::xfr::notify::send_notify(Some(&zone.name)).await {
            log_error!("NSUPDATE notify failed for zone {}: {}", zone.name, e);
        }

        log_info!(
            "NSUPDATE committed for zone {} with serial {}",
            zone.name,
            new_serial
        );
    }

    Ok(UpdateResult::Applied { changed })
}

async fn apply_single_update(
    zone: &Zone,
    update: &UpdateRecord,
    query_data: &[u8],
) -> Result<bool, UpdateError> {
    let owner_name = normalize_owner_name(&update.name, &zone.name)?;

    match update.class {
        CLASS_IN => add_record(zone, &owner_name, update, query_data).await,
        CLASS_ANY => delete_records(zone, &owner_name, update, true, query_data).await,
        CLASS_NONE => delete_records(zone, &owner_name, update, false, query_data).await,
        class => Err(UpdateError::Refused(format!(
            "unsupported update class: {}",
            class
        ))),
    }
}

async fn add_record(
    zone: &Zone,
    owner_name: &str,
    update: &UpdateRecord,
    query_data: &[u8],
) -> Result<bool, UpdateError> {
    let (record_type, value, priority) = rr_to_record_value(update, query_data)?;

    let relative_name = absolute_to_relative(owner_name, &zone.name)?;

    validate_nsupdate_add_constraints(zone, &relative_name, &record_type, &value)
        .await
        .map_err(|e| UpdateError::Refused(e.to_string()))?;

    if find_identical_record_in_zone(zone.id, &relative_name, &record_type, &value, priority)
        .await
        .map_err(|e| UpdateError::Internal(e.to_string()))?
        .is_some()
    {
        return Ok(false);
    }

    let created = RepositoryService::create_record(Record {
        id: 0,
        name: relative_name.clone(),
        record_type: record_type.clone(),
        value: value.clone(),
        ttl: Some(update.ttl as i32),
        priority,
        zone_id: zone.id,
        created_at: Utc::now(),
    })
    .await
    .map_err(|e| UpdateError::Internal(format!("failed to create record: {}", e)))?;

    log_zone_change(
        zone.id,
        "ADD",
        &created.name,
        &record_type,
        &value,
        created.ttl,
        created.priority,
    )
    .await?;

    Ok(true)
}

async fn delete_records(
    zone: &Zone,
    owner_name: &str,
    update: &UpdateRecord,
    is_rrset_delete: bool,
    query_data: &[u8],
) -> Result<bool, UpdateError> {
    let relative_name = absolute_to_relative(owner_name, &zone.name)?;
    let zone_records = RepositoryService::get_records_by_zone_id(zone.id)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to load records: {}", e)))?;

    let target_type = if update.rr_type == TYPE_ANY {
        None
    } else {
        Some(rr_type_to_record_type(update.rr_type)?)
    };

    let (target_value, target_priority) = if is_rrset_delete || update.rdata.is_empty() {
        (None, None)
    } else {
        let (_, value, priority) = rr_to_record_value(update, query_data)?;
        (Some(value), priority)
    };

    let mut matched: Vec<Record> = Vec::new();
    for record in zone_records {
        if !record.name.eq_ignore_ascii_case(&relative_name) {
            continue;
        }

        if let Some(ref typ) = target_type
            && &record.record_type != typ
        {
            continue;
        }

        if let Some(ref value) = target_value
            && !record.value.eq_ignore_ascii_case(value)
        {
            continue;
        }

        if let Some(pri) = target_priority
            && record.priority != Some(pri)
        {
            continue;
        }

        if record.record_type == RecordType::SOA {
            continue;
        }

        matched.push(record);
    }

    if matched.is_empty() {
        return Ok(false);
    }

    for record in &matched {
        RepositoryService::delete_record(record.id)
            .await
            .map_err(|e| UpdateError::Internal(format!("failed to delete record: {}", e)))?;

        log_zone_change(
            zone.id,
            "DEL",
            &record.name,
            &record.record_type,
            &record.value,
            record.ttl,
            record.priority,
        )
        .await?;
    }

    Ok(true)
}

pub(super) fn rr_to_record_value(
    update: &UpdateRecord,
    message: &[u8],
) -> Result<(RecordType, String, Option<i32>), UpdateError> {
    match update.rr_type {
        TYPE_A => {
            if update.rdata.len() != 4 {
                return Err(UpdateError::Refused("invalid A rdata length".to_string()));
            }
            let value = std::net::Ipv4Addr::new(
                update.rdata[0],
                update.rdata[1],
                update.rdata[2],
                update.rdata[3],
            )
            .to_string();
            Ok((RecordType::A, value, None))
        }
        TYPE_AAAA => {
            if update.rdata.len() != 16 {
                return Err(UpdateError::Refused(
                    "invalid AAAA rdata length".to_string(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&update.rdata[..16]);
            let value = std::net::Ipv6Addr::from(octets).to_string();
            Ok((RecordType::AAAA, value, None))
        }
        TYPE_CNAME => Ok((
            RecordType::CNAME,
            decode_name_from_rdata(message, update.rdata_start, update.rdata.len())
                .map_err(|e| UpdateError::Refused(format!("invalid CNAME rdata: {}", e)))?,
            None,
        )),
        TYPE_NS => Ok((
            RecordType::NS,
            decode_name_from_rdata(message, update.rdata_start, update.rdata.len())
                .map_err(|e| UpdateError::Refused(format!("invalid NS rdata: {}", e)))?,
            None,
        )),
        TYPE_PTR => Ok((
            RecordType::PTR,
            decode_name_from_rdata(message, update.rdata_start, update.rdata.len())
                .map_err(|e| UpdateError::Refused(format!("invalid PTR rdata: {}", e)))?,
            None,
        )),
        TYPE_TXT => Ok((
            RecordType::TXT,
            decode_txt_from_rdata(&update.rdata)
                .map_err(|e| UpdateError::Refused(format!("invalid TXT rdata: {}", e)))?,
            None,
        )),
        TYPE_MX => {
            if update.rdata.len() < 3 {
                return Err(UpdateError::Refused("invalid MX rdata length".to_string()));
            }

            let priority = i32::from(u16::from_be_bytes([update.rdata[0], update.rdata[1]]));
            let host =
                decode_name_from_rdata(message, update.rdata_start + 2, update.rdata.len() - 2)
                    .map_err(|e| UpdateError::Refused(format!("invalid MX rdata: {}", e)))?;
            Ok((RecordType::MX, host, Some(priority)))
        }
        _ => Err(UpdateError::Refused(format!(
            "unsupported rr type: {}",
            update.rr_type
        ))),
    }
}

pub(super) fn rr_type_to_record_type(rr_type: u16) -> Result<RecordType, UpdateError> {
    match rr_type {
        TYPE_A => Ok(RecordType::A),
        TYPE_AAAA => Ok(RecordType::AAAA),
        TYPE_CNAME => Ok(RecordType::CNAME),
        TYPE_MX => Ok(RecordType::MX),
        TYPE_TXT => Ok(RecordType::TXT),
        TYPE_NS => Ok(RecordType::NS),
        TYPE_PTR => Ok(RecordType::PTR),
        _ => Err(UpdateError::Refused(format!(
            "unsupported rr type: {}",
            rr_type
        ))),
    }
}

pub(super) fn normalize_owner_name(name: &str, zone_name: &str) -> Result<String, UpdateError> {
    let normalized_zone = to_fqdn(zone_name);
    let normalized_zone_no_dot = trim_dot(&normalized_zone).to_ascii_lowercase();

    let owner = if name == "." {
        return Err(UpdateError::NotZone(
            "root owner is not supported".to_string(),
        ));
    } else {
        to_fqdn(name)
    };

    let owner_no_dot = trim_dot(&owner).to_ascii_lowercase();

    if owner_no_dot == normalized_zone_no_dot
        || owner_no_dot.ends_with(&format!(".{}", normalized_zone_no_dot))
    {
        return Ok(owner);
    }

    Err(UpdateError::NotZone(format!(
        "owner '{}' is outside zone '{}'",
        owner, normalized_zone
    )))
}

pub(super) fn absolute_to_relative(owner: &str, zone_name: &str) -> Result<String, UpdateError> {
    let owner = to_fqdn(owner);
    let zone = to_fqdn(zone_name);

    if owner.eq_ignore_ascii_case(&zone) {
        return Ok("@".to_string());
    }

    let owner_lower = owner.to_ascii_lowercase();
    let zone_lower = zone.to_ascii_lowercase();

    if !owner_lower.ends_with(&zone_lower) {
        return Err(UpdateError::NotZone(format!(
            "owner '{}' is outside zone '{}'",
            owner, zone
        )));
    }

    let rel_len = owner.len() - zone.len();
    let rel = owner[..rel_len].trim_end_matches('.');
    Ok(rel.to_string())
}

fn to_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

fn trim_dot(name: &str) -> &str {
    name.trim_end_matches('.')
}

async fn bump_zone_serial(zone: &Zone) -> Result<i32, UpdateError> {
    let new_serial = generate_serial(zone.serial);

    RepositoryService::update_zone(Zone {
        serial: new_serial,
        ..zone.clone()
    })
    .await
    .map_err(|e| UpdateError::Internal(format!("failed to update zone serial: {}", e)))?;

    Ok(new_serial)
}

fn generate_serial(current_serial: i32) -> i32 {
    let now = Utc::now();
    let date_prefix = now.format("%Y%m%d").to_string().parse::<i32>().unwrap_or(0);
    let base_serial = date_prefix * 100;

    if base_serial > current_serial {
        base_serial
    } else {
        current_serial + 1
    }
}

async fn save_zone_snapshot(zone: &Zone, serial: i32) -> Result<(), UpdateError> {
    RepositoryService::upsert_zone_snapshot(ZoneSnapshot {
        id: 0,
        zone_id: zone.id,
        serial,
        primary_ns: zone.primary_ns.clone(),
        admin_email: zone.admin_email.replace('@', "."),
        ttl: zone.ttl,
        refresh: zone.refresh,
        retry: zone.retry,
        expire: zone.expire,
        minimum_ttl: zone.minimum_ttl,
        created_at: Utc::now(),
    })
    .await
    .map_err(|e| UpdateError::Internal(format!("failed to save zone snapshot: {}", e)))?;

    Ok(())
}

async fn log_zone_change(
    zone_id: i32,
    operation: &str,
    name: &str,
    record_type: &RecordType,
    value: &str,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Result<(), UpdateError> {
    let zone = RepositoryService::get_zone_by_id(zone_id)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to load zone for change: {}", e)))?
        .ok_or_else(|| UpdateError::Internal(format!("zone {} not found", zone_id)))?;

    let serial = generate_serial(zone.serial);

    RepositoryService::create_zone_change(ZoneChange {
        id: 0,
        zone_id,
        serial,
        operation: operation.to_string(),
        record_name: name.to_string(),
        record_type: record_type.to_string(),
        record_value: value.to_string(),
        record_ttl: ttl,
        record_priority: priority,
    })
    .await
    .map_err(|e| UpdateError::Internal(format!("failed to log zone change: {}", e)))?;

    Ok(())
}
