use super::parser::{UpdateRecord, UpdateRequest, decode_name_from_rdata, decode_txt_from_rdata};
use crate::{
    log_error, log_info,
    model::{
        record::{Record, RecordType},
        zone::Zone,
        zone_change::ZoneChange,
    },
    service,
    service::{
        RepositoryTx,
        record::{
            RecordService, validate_record_add_constraints_tx, validate_record_delete_constraints,
        },
        utils::generate_serial,
        zone::{ZoneService, snapshot::save_zone_snapshot_tx},
    },
    txt, xfr,
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
pub(super) enum UpdateError {
    Refused(String),
    NotAuth {
        msg: String,
        tsig: Option<TsigErrorResponse>,
    },
    YxDomain(String),
    YxRrset(String),
    NxDomain(String),
    NxRrset(String),
    NotZone(String),
    Internal(String),
}

#[derive(Debug, Clone)]
pub(super) struct TsigErrorResponse {
    pub name_canonical: Vec<u8>,
    pub algorithm_canonical: Vec<u8>,
    pub original_id: u16,
    pub time_signed: u64,
    pub fudge: u16,
    pub error: u16,
    pub other_data: Vec<u8>,
}

pub(super) enum UpdateResult {
    Applied { changed: bool },
}

pub(super) async fn apply_update(
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

    let mut tx = service::begin_tx("failed to begin NSUPDATE transaction")
        .await
        .map_err(|e| UpdateError::Internal(e.to_string()))?;

    let apply_result = async {
        let zone = ZoneService::find_tx(&mut tx, zone_name)
            .await
            .map_err(|e| UpdateError::Internal(format!("failed to load zone: {}", e)))?
            .ok_or_else(|| UpdateError::NotZone(format!("zone '{}' not found", zone_name)))?;

        super::prerequisite::evaluate_prerequisites_tx(
            &mut tx,
            &zone,
            &request.prerequisites,
            query_data,
        )
        .await?;

        let new_serial = generate_serial(Some(zone.serial));
        let mut changed = false;

        for update in &request.updates {
            let this_changed =
                apply_single_update(&mut tx, &zone, update, query_data, new_serial).await?;
            changed = changed || this_changed;
        }

        if changed {
            bump_zone_serial(&mut tx, &zone, new_serial).await?;
            save_zone_snapshot(&mut tx, &zone, new_serial).await?;
        }

        Ok::<(bool, Zone, i32), UpdateError>((changed, zone, new_serial))
    }
    .await;

    let (changed, zone, new_serial) = match apply_result {
        Ok(result) => {
            tx.commit().await.map_err(|e| {
                UpdateError::Internal(format!("failed to commit NSUPDATE transaction: {}", e))
            })?;
            result
        }
        Err(err) => {
            if let Err(e) = tx.rollback().await {
                log_error!("failed to rollback NSUPDATE transaction: {}", e);
            }
            return Err(err);
        }
    };

    if changed {
        if let Err(e) = xfr::notify::send_notify(Some(&zone.name)).await {
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
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    update: &UpdateRecord,
    query_data: &[u8],
    new_serial: i32,
) -> Result<bool, UpdateError> {
    let owner_name = normalize_owner_name(&update.name, &zone.name)?;

    match update.class {
        CLASS_IN => add_record(tx, zone, &owner_name, update, query_data, new_serial).await,
        CLASS_ANY => {
            delete_records(tx, zone, &owner_name, update, true, query_data, new_serial).await
        }
        CLASS_NONE => {
            delete_records(tx, zone, &owner_name, update, false, query_data, new_serial).await
        }
        class => Err(UpdateError::Refused(format!(
            "unsupported update class: {}",
            class
        ))),
    }
}

async fn add_record(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    owner_name: &str,
    update: &UpdateRecord,
    query_data: &[u8],
    new_serial: i32,
) -> Result<bool, UpdateError> {
    let (record_type, value, priority) = rr_to_record_value(update, query_data)?;

    let relative_name = absolute_to_relative(owner_name, &zone.name)?;

    validate_record_add_constraints_tx(
        tx,
        zone,
        &relative_name,
        &record_type,
        &value,
        priority,
        None,
    )
    .await
    .map_err(|e| UpdateError::Refused(e.to_string()))?;

    if RecordService::find_tx(
        tx,
        Some(zone.id),
        &relative_name,
        &record_type,
        Some(&value),
        priority,
        true,
    )
    .await
    .map_err(|e| UpdateError::Internal(e.to_string()))?
    .is_some()
    {
        return Ok(false);
    }

    let ttl = if update.ttl > i32::MAX as u32 {
        return Err(UpdateError::Refused(format!(
            "TTL value {} exceeds maximum allowed value ({})",
            update.ttl,
            i32::MAX
        )));
    } else {
        update.ttl as i32
    };

    let created = RecordService::create_tx(
        tx,
        Record {
            id: 0,
            name: relative_name.clone(),
            record_type: record_type.clone(),
            value: value.clone(),
            ttl: Some(ttl),
            priority,
            zone_id: zone.id,
            created_at: Utc::now(),
        },
    )
    .await
    .map_err(|e| UpdateError::Internal(format!("failed to create record: {}", e)))?;

    log_zone_change(
        tx,
        zone.id,
        new_serial,
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
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    owner_name: &str,
    update: &UpdateRecord,
    is_rrset_delete: bool,
    query_data: &[u8],
    new_serial: i32,
) -> Result<bool, UpdateError> {
    validate_delete_update_shape(update, is_rrset_delete)?;

    let relative_name = absolute_to_relative(owner_name, &zone.name)?;
    let zone_records = RecordService::list_by_zone_id_tx(tx, zone.id)
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
    for record in &zone_records {
        if !record.name.eq_ignore_ascii_case(&relative_name) {
            continue;
        }

        if let Some(ref typ) = target_type
            && &record.record_type != typ
        {
            continue;
        }

        if let Some(ref value) = target_value
            && !record_value_matches(&record.record_type, &record.value, value)
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

        matched.push(record.clone());
    }

    if matched.is_empty() {
        return Ok(false);
    }

    // Validate delete constraints
    validate_record_delete_constraints(zone, &zone_records, &matched)
        .map_err(|e| UpdateError::Refused(e.to_string()))?;

    for record in &matched {
        RecordService::delete_tx(tx, record.id)
            .await
            .map_err(|e| UpdateError::Internal(format!("failed to delete record: {}", e)))?;

        log_zone_change(
            tx,
            zone.id,
            new_serial,
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

pub(super) fn record_value_matches(
    record_type: &RecordType,
    stored_value: &str,
    target_value: &str,
) -> bool {
    match record_type {
        RecordType::CNAME | RecordType::NS | RecordType::PTR | RecordType::MX => {
            stored_value.eq_ignore_ascii_case(target_value)
        }
        _ => stored_value == target_value,
    }
}

fn validate_delete_update_shape(
    update: &UpdateRecord,
    is_rrset_delete: bool,
) -> Result<(), UpdateError> {
    if update.ttl != 0 {
        return Err(UpdateError::Refused(
            "delete update TTL must be 0".to_string(),
        ));
    }

    if is_rrset_delete {
        if !update.rdata.is_empty() {
            return Err(UpdateError::Refused(
                "ANY-class delete must have empty rdata".to_string(),
            ));
        }
    } else {
        if update.rr_type == TYPE_ANY {
            return Err(UpdateError::Refused(
                "NONE-class delete must specify rrtype".to_string(),
            ));
        }

        if update.rdata.is_empty() {
            return Err(UpdateError::Refused(
                "NONE-class delete must specify rdata".to_string(),
            ));
        }
    }

    Ok(())
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
        TYPE_TXT => {
            decode_txt_from_rdata(&update.rdata)
                .map_err(|e| UpdateError::Refused(format!("invalid TXT rdata: {}", e)))?;
            Ok((
                RecordType::TXT,
                txt::encode_raw_txt_rdata(&update.rdata),
                None,
            ))
        }
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
    let zone_suffix = format!(".{}", zone_lower);

    if !owner_lower.ends_with(&zone_suffix) {
        return Err(UpdateError::NotZone(format!(
            "owner '{}' is outside zone '{}'",
            owner, zone
        )));
    }

    let rel_len = owner.len() - zone.len() - 1;
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

async fn bump_zone_serial(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    new_serial: i32,
) -> Result<(), UpdateError> {
    ZoneService::update_tx(
        tx,
        Zone {
            serial: new_serial,
            ..zone.clone()
        },
    )
    .await
    .map_err(|e| UpdateError::Internal(format!("failed to update zone serial: {}", e)))?;

    Ok(())
}

async fn save_zone_snapshot(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    serial: i32,
) -> Result<(), UpdateError> {
    save_zone_snapshot_tx(tx, zone, serial)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to save zone snapshot: {}", e)))?;

    Ok(())
}

async fn log_zone_change(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    serial: i32,
    operation: &str,
    name: &str,
    record_type: &RecordType,
    value: &str,
    ttl: Option<i32>,
    priority: Option<i32>,
) -> Result<(), UpdateError> {
    ZoneService::create_change_tx(
        tx,
        ZoneChange {
            id: 0,
            zone_id,
            serial,
            operation: operation.to_string(),
            record_name: name.to_string(),
            record_type: record_type.to_string(),
            record_value: value.to_string(),
            record_ttl: ttl,
            record_priority: priority,
        },
    )
    .await
    .map_err(|e| UpdateError::Internal(format!("failed to log zone change: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CLASS_ANY, CLASS_IN, CLASS_NONE, TYPE_A, TYPE_ANY, TYPE_TXT, UpdateError,
        absolute_to_relative, record_value_matches, rr_to_record_value,
        validate_delete_update_shape,
    };
    use crate::model::record::RecordType;
    use crate::nsupdate::parser::UpdateRecord;

    #[test]
    fn absolute_to_relative_accepts_apex() {
        let relative = absolute_to_relative("example.com.", "example.com.").unwrap();
        assert_eq!(relative, "@");
    }

    #[test]
    fn absolute_to_relative_accepts_subdomain_at_label_boundary() {
        let relative = absolute_to_relative("www.example.com.", "example.com.").unwrap();
        assert_eq!(relative, "www");
    }

    #[test]
    fn absolute_to_relative_rejects_partial_suffix_match() {
        let err = absolute_to_relative("aexample.com.", "example.com.").unwrap_err();
        assert!(matches!(err, UpdateError::NotZone(_)));
    }

    #[test]
    fn validate_delete_update_shape_accepts_any_class_rrset_delete() {
        let update = update_record(TYPE_A, CLASS_ANY, 0, Vec::new());

        validate_delete_update_shape(&update, true).unwrap();
    }

    #[test]
    fn validate_delete_update_shape_accepts_none_class_exact_delete() {
        let update = update_record(TYPE_A, CLASS_NONE, 0, vec![192, 0, 2, 1]);

        validate_delete_update_shape(&update, false).unwrap();
    }

    #[test]
    fn validate_delete_update_shape_rejects_delete_with_nonzero_ttl() {
        let update = update_record(TYPE_A, CLASS_ANY, 60, Vec::new());
        let err = validate_delete_update_shape(&update, true).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    #[test]
    fn validate_delete_update_shape_rejects_any_class_delete_with_rdata() {
        let update = update_record(TYPE_A, CLASS_ANY, 0, vec![192, 0, 2, 1]);
        let err = validate_delete_update_shape(&update, true).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    #[test]
    fn validate_delete_update_shape_rejects_none_class_delete_without_rdata() {
        let update = update_record(TYPE_A, CLASS_NONE, 0, Vec::new());
        let err = validate_delete_update_shape(&update, false).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    #[test]
    fn validate_delete_update_shape_rejects_none_class_delete_with_type_any() {
        let update = update_record(TYPE_ANY, CLASS_NONE, 0, vec![192, 0, 2, 1]);
        let err = validate_delete_update_shape(&update, false).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    #[test]
    fn record_value_matches_is_case_sensitive_for_txt() {
        assert!(record_value_matches(&RecordType::TXT, "Hello", "Hello"));
        assert!(!record_value_matches(&RecordType::TXT, "Hello", "hello"));
    }

    #[test]
    fn rr_to_record_value_preserves_txt_character_string_boundaries() {
        let first = UpdateRecord {
            name: "txt.example.com.".to_string(),
            rr_type: TYPE_TXT,
            class: CLASS_IN,
            ttl: 300,
            rdata: vec![2, b'a', b'b', 1, b'c'],
            rdata_start: 0,
        };
        let second = UpdateRecord {
            name: "txt.example.com.".to_string(),
            rr_type: TYPE_TXT,
            class: CLASS_IN,
            ttl: 300,
            rdata: vec![1, b'a', 2, b'b', b'c'],
            rdata_start: 0,
        };

        let (_, first_value, _) = rr_to_record_value(&first, &first.rdata).unwrap();
        let (_, second_value, _) = rr_to_record_value(&second, &second.rdata).unwrap();

        assert_ne!(first_value, second_value);
        assert!(record_value_matches(
            &RecordType::TXT,
            &first_value,
            &first_value
        ));
        assert!(!record_value_matches(
            &RecordType::TXT,
            &first_value,
            &second_value
        ));
    }

    #[test]
    fn record_value_matches_ignores_case_for_name_like_values() {
        assert!(record_value_matches(
            &RecordType::NS,
            "Ns1.Example.Com.",
            "ns1.example.com."
        ));
        assert!(record_value_matches(
            &RecordType::MX,
            "Mail.Example.Com.",
            "mail.example.com."
        ));
    }

    fn update_record(rr_type: u16, class: u16, ttl: u32, rdata: Vec<u8>) -> UpdateRecord {
        UpdateRecord {
            name: "www.example.com.".to_string(),
            rr_type,
            class,
            ttl,
            rdata,
            rdata_start: 0,
        }
    }
}
