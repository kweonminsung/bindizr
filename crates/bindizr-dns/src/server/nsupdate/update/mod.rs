use bindizr_core::{config, dns::name::to_fqdn};
use chrono::Utc;
use domain::{
    base::{
        iana::{Class, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::{A, Aaaa, Mx, Txt},
};

use super::{
    auth::ResponseSigner,
    parser::{UpdateRecord, UpdateRequest, presentation_name},
};
use crate::{
    log_error, log_info,
    model::{
        record::{Record, RecordType},
        tsig_key::TsigKey,
        zone::Zone,
        zone_change::ZoneChange,
    },
    service,
    service::{
        RepositoryTx,
        record::{RecordService, validate_add_constraints_tx, validate_delete_constraints},
        serial::generate_serial,
        tsig_key::TsigKeyService,
        zone::{
            ZoneService,
            snapshot::save_zone_snapshot_tx,
            tsig_policy::{self, ZoneTsigPolicyService},
        },
    },
    txt,
};

#[derive(Debug)]
pub(super) enum UpdateError {
    Refused(String),
    /// TSIG validation failed. Carries the complete NOTAUTH wire response,
    /// built during validation because it must echo (or sign against) the
    /// request's TSIG record (RFC 8945 §5.2–5.3).
    TsigFailed {
        msg: String,
        response: Vec<u8>,
    },
    YxDomain(String),
    YxRrset(String),
    NxDomain(String),
    NxRrset(String),
    NotZone(String),
    Internal(String),
}

pub(super) enum UpdateResult {
    Applied { changed: bool },
}

/// Outcome of the transactional part of an applied update.
struct AppliedUpdate {
    changed: bool,
    zone: Zone,
    new_serial: i32,
}

/// Apply an UPDATE request. The returned signer is `Some` once the request's
/// TSIG was validated, so the response — success or failure — can be signed.
pub(super) async fn apply_update(
    request: UpdateRequest,
    query_data: &[u8],
) -> (Result<UpdateResult, UpdateError>, Option<ResponseSigner>) {
    let mut signer = None;
    let result = apply_update_inner(request, query_data, &mut signer).await;
    (result, signer)
}

async fn apply_update_inner(
    request: UpdateRequest,
    query_data: &[u8],
    signer: &mut Option<ResponseSigner>,
) -> Result<UpdateResult, UpdateError> {
    let zone_name = trim_dot(&request.zone_name);
    if zone_name.is_empty() {
        return Err(UpdateError::NotZone(
            "root zone is not supported".to_string(),
        ));
    }

    let mut tx = service::begin_tx("failed to begin NSUPDATE transaction")
        .await
        .map_err(|e| UpdateError::Internal(e.to_string()))?;

    let apply_result: Result<AppliedUpdate, UpdateError> = async {
        // Authenticate before the zone lookup: keys are zone-independent, and
        // this lets even NOTZONE/REFUSED responses be signed.
        let key = authenticate_request(&mut tx, &request, query_data, signer).await?;

        let zone = ZoneService::find_tx(&mut tx, zone_name)
            .await
            .map_err(|e| UpdateError::Internal(format!("failed to load zone: {}", e)))?
            .ok_or_else(|| UpdateError::NotZone(format!("zone '{}' not found", zone_name)))?;

        authorize_key(&mut tx, &zone, key.as_ref(), &request).await?;

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

        Ok(AppliedUpdate {
            changed,
            zone,
            new_serial,
        })
    }
    .await;

    let AppliedUpdate {
        changed,
        zone,
        new_serial,
    } = match apply_result {
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
        log_info!(
            "NSUPDATE committed for zone {} with serial {}",
            zone.name,
            new_serial
        );

        if config::get_bindizr_config().dns.notify_after_update {
            if let Err(e) = crate::client::notify::send_notify(Some(&zone.name), false).await {
                log_error!("NSUPDATE notify failed for zone {}: {}", zone.name, e);
            }
        }
    }

    Ok(UpdateResult::Applied { changed })
}

/// Verify the request's TSIG signature and record the response-signing
/// context. Returns the signing key, or `None` for an unsigned request
/// accepted via `dns.nsupdate_allow_unsigned` (not recommended in
/// production); signed requests are always verified.
async fn authenticate_request(
    tx: &mut RepositoryTx<'_>,
    request: &UpdateRequest,
    query_data: &[u8],
    signer: &mut Option<ResponseSigner>,
) -> Result<Option<TsigKey>, UpdateError> {
    let tsig = match &request.tsig {
        Some(tsig) => tsig,
        None => {
            if config::get_bindizr_config().dns.nsupdate_allow_unsigned {
                return Ok(None);
            }
            return Err(UpdateError::Refused(
                "unsigned NSUPDATE refused: no TSIG record present".to_string(),
            ));
        }
    };

    let key = TsigKeyService::find_by_name_tx(tx, &tsig.name)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to load TSIG key: {}", e)))?;

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let domain_key = key.as_ref().map(super::auth::to_domain_key).transpose()?;
    *signer = Some(super::auth::validate_tsig(query_data, domain_key)?);

    Ok(key)
}

/// Authorize an authenticated request: global keys may update anything, other
/// keys need a zone policy matching every update RR. `key` is `None` for an
/// accepted unsigned request, which skips authorization entirely.
async fn authorize_key(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    key: Option<&TsigKey>,
    request: &UpdateRequest,
) -> Result<(), UpdateError> {
    let key = match key {
        None => return Ok(()),
        Some(key) if key.is_global => return Ok(()),
        Some(key) => key,
    };

    let policies = ZoneTsigPolicyService::get_by_zone_and_key_tx(tx, zone.id, key.id)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to load TSIG policies: {}", e)))?;

    if policies.is_empty() {
        return Err(UpdateError::Refused(format!(
            "TSIG key '{}' is not authorized for zone '{}'",
            key.name, zone.name
        )));
    }

    for update in &request.updates {
        let owner_name = normalize_owner_name(&update.name, &zone.name)?;
        let relative_name = absolute_to_relative(&owner_name, &zone.name)?;
        let record_type = if update.rr_type == Rtype::ANY {
            None
        } else {
            Some(rr_type_to_record_type(update.rr_type)?)
        };

        if !tsig_policy::authorize_update(&policies, &relative_name, record_type.as_ref()) {
            return Err(UpdateError::Refused(format!(
                "TSIG key '{}' is not authorized to update '{}' ({}) in zone '{}'",
                key.name,
                relative_name,
                record_type
                    .as_ref()
                    .map(|record_type| record_type.as_str())
                    .unwrap_or("ANY"),
                zone.name
            )));
        }
    }

    Ok(())
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
        Class::IN => add_record(tx, zone, &owner_name, update, query_data, new_serial).await,
        Class::ANY => {
            delete_records(tx, zone, &owner_name, update, true, query_data, new_serial).await
        }
        Class::NONE => {
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

    if update.ttl > i32::MAX as u32 {
        return Err(UpdateError::Refused(format!(
            "TTL value {} exceeds maximum allowed value ({})",
            update.ttl,
            i32::MAX
        )));
    }
    let ttl = update.ttl as i32;

    validate_add_constraints_tx(
        tx,
        zone,
        &relative_name,
        &record_type,
        &value,
        Some(ttl),
        priority,
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

    let created = RecordService::create_tx(
        tx,
        Record {
            id: 0,
            name: relative_name,
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

    let target_type = if update.rr_type == Rtype::ANY {
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

    validate_delete_constraints(zone, &matched).map_err(|e| UpdateError::Refused(e.to_string()))?;

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
        if update.rr_type == Rtype::ANY {
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

/// Parses one rdata field in place inside the full message — so names may
/// chase compression pointers — and requires the parse to consume it exactly.
fn parse_rdata<'a, T>(
    message: &'a [u8],
    update: &UpdateRecord,
    what: &str,
    parse: impl FnOnce(&mut Parser<'a, [u8]>) -> Option<T>,
) -> Result<T, UpdateError> {
    let refused = || UpdateError::Refused(format!("invalid {} rdata", what));

    let mut parser = Parser::from_ref(message);
    parser.advance(update.rdata_start).map_err(|_| refused())?;
    let value = parse(&mut parser).ok_or_else(refused)?;

    if parser.pos() != update.rdata_start + update.rdata.len() {
        return Err(refused());
    }

    Ok(value)
}

pub(super) fn rr_to_record_value(
    update: &UpdateRecord,
    message: &[u8],
) -> Result<(RecordType, String, Option<i32>), UpdateError> {
    match rr_type_to_record_type(update.rr_type)? {
        RecordType::A => {
            let data = parse_rdata(message, update, "A", |parser| A::parse(parser).ok())?;
            Ok((RecordType::A, data.addr().to_string(), None))
        }
        RecordType::AAAA => {
            let data = parse_rdata(message, update, "AAAA", |parser| Aaaa::parse(parser).ok())?;
            Ok((RecordType::AAAA, data.addr().to_string(), None))
        }
        record_type @ (RecordType::CNAME | RecordType::NS | RecordType::PTR) => {
            let name = parse_rdata(message, update, record_type.as_str(), |parser| {
                ParsedName::parse(parser).ok()
            })?;
            let value = presentation_name(&name).map_err(|e| {
                UpdateError::Refused(format!("invalid {} rdata: {}", record_type.as_str(), e))
            })?;
            Ok((record_type, value, None))
        }
        RecordType::TXT => {
            let data = Txt::from_octets(update.rdata.as_slice())
                .map_err(|e| UpdateError::Refused(format!("invalid TXT rdata: {}", e)))?;
            // Stored TXT values must decode back into strings, so reject
            // non-UTF-8 character-strings even though the wire allows them.
            for charstr in data.iter_charstrs() {
                if std::str::from_utf8(charstr.as_slice()).is_err() {
                    return Err(UpdateError::Refused("invalid TXT rdata".to_string()));
                }
            }
            Ok((
                RecordType::TXT,
                txt::encode_raw_txt_rdata(&update.rdata),
                None,
            ))
        }
        RecordType::MX => {
            let data = parse_rdata(message, update, "MX", |parser| Mx::parse(parser).ok())?;
            let host = presentation_name(data.exchange())
                .map_err(|e| UpdateError::Refused(format!("invalid MX rdata: {}", e)))?;
            Ok((RecordType::MX, host, Some(i32::from(data.preference()))))
        }
        _ => Err(UpdateError::Refused(format!(
            "unsupported rr type: {}",
            update.rr_type
        ))),
    }
}

/// Record types updatable via nsupdate; SOA and SRV are deliberately excluded.
pub(super) fn rr_type_to_record_type(rr_type: Rtype) -> Result<RecordType, UpdateError> {
    match rr_type {
        Rtype::A => Ok(RecordType::A),
        Rtype::NS => Ok(RecordType::NS),
        Rtype::CNAME => Ok(RecordType::CNAME),
        Rtype::PTR => Ok(RecordType::PTR),
        Rtype::MX => Ok(RecordType::MX),
        Rtype::TXT => Ok(RecordType::TXT),
        Rtype::AAAA => Ok(RecordType::AAAA),
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
    // Store lowercase like the JSON/CLI path: owner names are case-insensitive and
    // the scoped conflict lookups bind lowercased, so mixed case would escape them.
    Ok(rel.to_ascii_lowercase())
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
mod tests;
