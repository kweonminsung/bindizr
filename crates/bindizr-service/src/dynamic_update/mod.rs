//! RFC 2136 dynamic updates, from the point the wire message is decoded.
//! Prerequisite evaluation, per-key authorization, and the transactional apply
//! live here; the DNS front end owns the message format, TSIG, and rdata.

use bindizr_db::repository::LockLevel;

mod prerequisite;
#[cfg(test)]
mod tests;

use bindizr_core::dns::name::{OwnerName, ParseNameError, ZoneName, to_fqdn};
use chrono::Utc;
use prerequisite::evaluate_prerequisites_tx;

use crate::{
    RepositoryTx,
    dnssec::DnssecService,
    error::ServiceError,
    log_error, log_info,
    model::{
        record::{Record, RecordType},
        tsig_key::TsigKey,
        zone::Zone,
    },
    record::{AddOutcome, RecordService, validate_delete_constraints},
    repository::RepositoryService,
    serial::generate_serial,
    zone::{ZoneService, tsig_policy},
};

/// Why an update was not applied, in the terms RFC 2136, Section 2.2 gives the
/// response code.
#[derive(Debug)]
pub enum DynamicUpdateError {
    Refused(String),
    YxDomain(String),
    YxRrset(String),
    NxDomain(String),
    NxRrset(String),
    NotZone(String),
    Internal(String),
}

/// A service error the requester could fix is REFUSED; a backend fault is
/// SERVFAIL.
impl From<ServiceError> for DynamicUpdateError {
    fn from(err: ServiceError) -> Self {
        if err.code.http_status() < 500 {
            DynamicUpdateError::Refused(err.to_string())
        } else {
            DynamicUpdateError::Internal(err.to_string())
        }
    }
}

/// A condition the zone must satisfy before any update is applied
/// (RFC 2136, Section 2.4). Owner names are absolute, as they arrive on the wire.
pub enum Prerequisite {
    /// CLASS ANY, TYPE ANY: the owner name must exist.
    NameInUse { name: String },
    /// CLASS NONE, TYPE ANY: the owner name must not exist.
    NameNotInUse { name: String },
    /// CLASS ANY: the RRset must exist.
    RrsetInUse {
        name: String,
        record_type: RecordType,
    },
    /// CLASS NONE: the RRset must not exist.
    RrsetNotInUse {
        name: String,
        record_type: RecordType,
    },
    /// CLASS IN: this exact RR must exist.
    RrInUse {
        name: String,
        record_type: RecordType,
        /// TXT arrives row-encoded; every other type in presentation form.
        value: String,
        priority: Option<i32>,
    },
}

/// One update to apply (RFC 2136, Section 2.5). Owner names are absolute.
pub enum UpdateOp {
    /// CLASS IN: add the RR.
    Add {
        name: String,
        record_type: RecordType,
        /// TXT arrives row-encoded; every other type in presentation form.
        value: String,
        ttl: i32,
        priority: Option<i32>,
    },
    /// CLASS ANY: delete an RRset, or every RRset at the owner name when
    /// `record_type` is `None` (wire TYPE ANY).
    DeleteRrset {
        name: String,
        record_type: Option<RecordType>,
    },
    /// CLASS NONE: delete the RRs carrying exactly this rdata.
    DeleteRr {
        name: String,
        record_type: RecordType,
        value: String,
        priority: Option<i32>,
    },
}

impl UpdateOp {
    fn name(&self) -> &str {
        match self {
            UpdateOp::Add { name, .. }
            | UpdateOp::DeleteRrset { name, .. }
            | UpdateOp::DeleteRr { name, .. } => name,
        }
    }

    /// The type this update touches; `None` for a whole-name delete.
    fn record_type(&self) -> Option<&RecordType> {
        match self {
            UpdateOp::Add { record_type, .. } | UpdateOp::DeleteRr { record_type, .. } => {
                Some(record_type)
            }
            UpdateOp::DeleteRrset { record_type, .. } => record_type.as_ref(),
        }
    }
}

/// A decoded UPDATE message: the zone it targets, the key that signed it, and
/// the sections to evaluate and apply.
pub struct DynamicUpdate {
    pub zone_name: String,
    /// The verified signing key, or `None` for a request accepted unsigned.
    pub key: Option<TsigKey>,
    pub prerequisites: Vec<Prerequisite>,
    pub updates: Vec<UpdateOp>,
}

/// Applies RFC 2136 dynamic updates to zone data.
pub struct DynamicUpdateService;

impl DynamicUpdateService {
    /// Apply an update as one transaction, reporting whether it changed
    /// anything. On a change the zone serial advances once and a NOTIFY is
    /// sent after commit.
    pub async fn apply(update: DynamicUpdate) -> Result<bool, DynamicUpdateError> {
        let mut tx = RepositoryService::begin_tx("failed to begin NSUPDATE transaction").await?;

        let apply_result: Result<(bool, Zone, i32), DynamicUpdateError> = async {
            let zone =
                ZoneService::find_by_name_tx(&mut tx, &update.zone_name, LockLevel::Exclusive)
                    .await?
                    .ok_or_else(|| {
                        DynamicUpdateError::NotZone(format!(
                            "zone '{}' not found",
                            update.zone_name
                        ))
                    })?;

            authorize_key(&mut tx, &zone, update.key.as_ref(), &update.updates).await?;
            evaluate_prerequisites_tx(&mut tx, &zone, &update.prerequisites).await?;

            // An exhausted serial cannot advance, so refuse rather than commit
            // changes secondaries could never detect.
            let new_serial = generate_serial(Some(zone.serial))?;
            let mut changed = false;

            for op in &update.updates {
                changed |= apply_op(&mut tx, &zone, op, new_serial).await?;
            }

            if changed {
                DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
                // Bump the serial and version it so secondaries detect the change via
                // SOA/NOTIFY and can serve it as an IXFR delta.
                ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;
            }

            Ok((changed, zone, new_serial))
        }
        .await;

        let (changed, zone, new_serial) =
            RepositoryService::finish_tx(tx, apply_result, "failed to commit NSUPDATE transaction")
                .await?;

        if changed {
            log_info!(
                "NSUPDATE committed for zone {} with serial {}",
                zone.name,
                new_serial
            );

            // Queue through the service like every other mutation path, so
            // `dns.notify_mode` governs RFC 2136 writes too.
            if let Err(e) = crate::notify::send_notify_after_update(Some(zone.name.as_str())).await
            {
                log_error!("NSUPDATE notify failed for zone {}: {}", zone.name, e);
            }
        }

        Ok(changed)
    }
}

/// Authorize an authenticated request: global keys may update anything, other
/// keys need a zone policy matching every update RR. `key` is `None` for an
/// accepted unsigned request, which skips authorization entirely.
async fn authorize_key(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    key: Option<&TsigKey>,
    updates: &[UpdateOp],
) -> Result<(), DynamicUpdateError> {
    let key = match key {
        None => return Ok(()),
        Some(key) if key.is_global => return Ok(()),
        Some(key) => key,
    };

    // Share-lock the grants so a concurrent revocation waits for this
    // transaction instead of racing it.
    let policies = RepositoryService::list_zone_tsig_policies_by_zone_id_and_key_id_tx(
        tx,
        zone.id,
        key.id,
        LockLevel::Shared,
    )
    .await?;

    if policies.is_empty() {
        return Err(DynamicUpdateError::Refused(format!(
            "TSIG key '{}' is not authorized for zone '{}'",
            key.name, zone.name
        )));
    }

    for op in updates {
        let owner = owner_in_zone(op.name(), &zone.name)?;
        if !tsig_policy::authorize_update(&policies, &owner, op.record_type()) {
            return Err(DynamicUpdateError::Refused(format!(
                "TSIG key '{}' is not authorized to update '{}' ({}) in zone '{}'",
                key.name,
                owner,
                op.record_type().map_or("ANY", RecordType::as_str),
                zone.name
            )));
        }
    }

    Ok(())
}

async fn apply_op(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    op: &UpdateOp,
    new_serial: i32,
) -> Result<bool, DynamicUpdateError> {
    match op {
        UpdateOp::Add {
            name,
            record_type,
            value,
            ttl,
            priority,
        } => {
            add_record(
                tx,
                zone,
                name,
                record_type,
                value,
                *ttl,
                *priority,
                new_serial,
            )
            .await
        }
        UpdateOp::DeleteRrset { name, record_type } => {
            delete_matching(tx, zone, name, record_type.as_ref(), None, None, new_serial).await
        }
        UpdateOp::DeleteRr {
            name,
            record_type,
            value,
            priority,
        } => {
            delete_matching(
                tx,
                zone,
                name,
                Some(record_type),
                Some(value.as_str()),
                *priority,
                new_serial,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn add_record(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    name: &str,
    record_type: &RecordType,
    value: &str,
    ttl: i32,
    priority: Option<i32>,
    new_serial: i32,
) -> Result<bool, DynamicUpdateError> {
    let owner = owner_in_zone(name, &zone.name)?;

    // Row-encode so nsupdate stores the same spelling as the other write
    // paths; TXT arrives already encoded from the wire rdata.
    let value = if *record_type == RecordType::TXT {
        value.to_string()
    } else {
        record_type.encoded_value(value, priority).map_err(|e| {
            DynamicUpdateError::Refused(format!("invalid {} rdata: {}", record_type.as_str(), e))
        })?
    };

    let outcome =
        RecordService::validate_add_tx(tx, zone, &owner, record_type, &value, ttl, priority)
            .await?;

    // RFC 2136, Section 3.4.2.2: an rdata-identical add is a silent no-op. The
    // TTL-replace clause is not implemented; RRset TTLs change via the API.
    if matches!(outcome, AddOutcome::Duplicate) {
        return Ok(false);
    }

    RecordService::insert_records_with_changes_tx(
        tx,
        zone.id,
        new_serial,
        &[Record {
            id: 0,
            name: owner,
            record_type: record_type.clone(),
            value,
            ttl,
            priority,
            zone_id: zone.id,
            created_at: Utc::now(),
        }],
    )
    .await?;

    Ok(true)
}

/// Delete every record at `name` matching the given type and (optionally)
/// rdata. `record_type` is `None` for a whole-name delete.
async fn delete_matching(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    name: &str,
    record_type: Option<&RecordType>,
    value: Option<&str>,
    priority: Option<i32>,
    new_serial: i32,
) -> Result<bool, DynamicUpdateError> {
    let owner = owner_in_zone(name, &zone.name)?;
    // Only records at the owner name can match, so lock just those.
    let owner_records =
        RepositoryService::list_records_by_name_tx(tx, zone.id, &owner, LockLevel::Exclusive)
            .await?;

    let mut matched: Vec<Record> = Vec::new();
    for record in &owner_records {
        if let Some(record_type) = record_type
            && &record.record_type != record_type
        {
            continue;
        }

        // Priority is filtered separately, so compare rdata alone.
        if let Some(value) = value
            && !record
                .record_type
                .values_equal(&record.value, None, value, None)
        {
            continue;
        }

        if let Some(priority) = priority
            && record.priority != Some(priority)
        {
            continue;
        }

        matched.push(record.clone());
    }

    if matched.is_empty() {
        return Ok(false);
    }

    validate_delete_constraints(zone, &matched)
        .map_err(|e| DynamicUpdateError::Refused(e.to_string()))?;

    RecordService::delete_records_with_changes_tx(tx, zone.id, new_serial, &matched).await?;

    Ok(true)
}

/// The owner of an update RR. The wire carries owners absolutely, so a name
/// outside the zone is NOTZONE rather than something to qualify.
fn owner_in_zone(name: &str, zone_name: &ZoneName) -> Result<OwnerName, DynamicUpdateError> {
    if name.trim_end_matches('.').is_empty() {
        return Err(DynamicUpdateError::NotZone(
            "root owner is not supported".to_string(),
        ));
    }

    OwnerName::parse_absolute_in_zone(name, zone_name).map_err(|e| match e {
        ParseNameError::OutsideZone => DynamicUpdateError::NotZone(format!(
            "owner '{}' is outside zone '{}'",
            to_fqdn(name),
            zone_name.to_fqdn()
        )),
        other => DynamicUpdateError::Refused(format!("owner '{}' {}", to_fqdn(name), other)),
    })
}
