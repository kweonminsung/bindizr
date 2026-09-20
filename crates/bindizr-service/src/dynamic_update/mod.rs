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
    model::{
        record::{Record, RecordType},
        tsig_key::TsigKey,
        zone::Zone,
    },
    record::{AddOutcome, RecordService, matches_record},
    repository::RepositoryService,
    serial::generate_serial,
    tsig_key::grant::{authorize_prerequisite, authorize_update},
    zone::{ZoneService, version::ChangeSubject},
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
    /// Map a service failure to the corresponding dynamic update error.
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
    /// CLASS IN: with the others of its name and type, the RRset must equal
    /// the zone's (RFC 2136, Section 3.2.3).
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
    AddRr {
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
    /// Return the owner name targeted by this update operation.
    fn name(&self) -> &str {
        match self {
            UpdateOp::AddRr { name, .. }
            | UpdateOp::DeleteRrset { name, .. }
            | UpdateOp::DeleteRr { name, .. } => name,
        }
    }

    /// The type this update touches; `None` for a whole-name delete.
    fn record_type(&self) -> Option<&RecordType> {
        match self {
            UpdateOp::AddRr { record_type, .. } | UpdateOp::DeleteRr { record_type, .. } => {
                Some(record_type)
            }
            UpdateOp::DeleteRrset { record_type, .. } => record_type.as_ref(),
        }
    }
}

/// A decoded UPDATE message: the zone it targets, the key that signed it, and
/// the sections to evaluate and apply.
pub struct DynamicUpdate {
    pub zone_name: ZoneName,
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
            let zone = ZoneService::find_served_by_name_tx(
                &mut tx,
                update.zone_name.as_str(),
                LockLevel::Exclusive,
            )
            .await?
            .ok_or_else(|| {
                DynamicUpdateError::NotZone(format!("zone '{}' not found", update.zone_name))
            })?;

            authorize_key_tx(
                &mut tx,
                &zone,
                update.key.as_ref(),
                &update.prerequisites,
                &update.updates,
            )
            .await?;
            evaluate_prerequisites_tx(&mut tx, &zone, &update.prerequisites).await?;

            // An exhausted serial cannot advance, so refuse rather than commit
            // changes secondaries could never detect.
            let new_serial = generate_serial(Some(zone.serial))?;
            let mut changed = false;

            for op in &update.updates {
                changed |= apply_op_tx(&mut tx, &zone, op, new_serial).await?;
            }

            if changed {
                DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
                // Bump the serial and version it so secondaries detect the change via
                // SOA/NOTIFY and can serve it as an IXFR delta.
                ZoneService::advance_serial_tx(
                    &mut tx,
                    &zone,
                    new_serial,
                    &ChangeSubject::nsupdate(update.key.as_ref().map(|key| key.name.as_str())),
                )
                .await?;
            }

            Ok((changed, zone, new_serial))
        }
        .await;

        let (changed, zone, new_serial) =
            RepositoryService::finish_tx(tx, apply_result, "failed to commit NSUPDATE transaction")
                .await?;

        if changed {
            log::info!(
                "event=nsupdate_apply zone={} serial={}",
                zone.name,
                new_serial
            );

            // Queue through the service like every other mutation path, so
            // `dns.notify.batch_ms` governs RFC 2136 writes too.
            if let Err(e) = crate::notify::send_notify_after_update(Some(zone.name.as_str())).await
            {
                log::error!("NSUPDATE notify failed for zone {}: {}", zone.name, e);
            }
        }

        Ok(changed)
    }
}

/// Authorize an authenticated request: global keys may do anything, other
/// keys need a grant reaching every prerequisite and every update RR. `key`
/// is `None` for an accepted unsigned request, which skips authorization
/// entirely.
async fn authorize_key_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    key: Option<&TsigKey>,
    prerequisites: &[Prerequisite],
    updates: &[UpdateOp],
) -> Result<(), DynamicUpdateError> {
    let key = match key {
        None => return Ok(()),
        Some(key) if key.is_global => return Ok(()),
        Some(key) => key,
    };

    // Share-lock the grants so a concurrent revocation waits for this
    // transaction instead of racing it.
    let grants = RepositoryService::list_tsig_grants_by_zone_id_and_key_id_tx(
        tx,
        zone.id,
        key.id,
        LockLevel::Shared,
    )
    .await?;

    if grants.is_empty() {
        return Err(DynamicUpdateError::Refused(format!(
            "TSIG key '{}' is not authorized for zone '{}'",
            key.name, zone.name
        )));
    }

    // A prerequisite reads what it names, so the grant is checked before it
    // is evaluated, ahead of where RFC 2136, Section 3.3 puts permissions.
    for prerequisite in prerequisites {
        let (name, record_type) = match prerequisite {
            Prerequisite::NameInUse { name } | Prerequisite::NameNotInUse { name } => (name, None),
            Prerequisite::RrsetInUse { name, record_type }
            | Prerequisite::RrsetNotInUse { name, record_type }
            | Prerequisite::RrInUse {
                name, record_type, ..
            } => (name, Some(record_type)),
        };
        let owner = parse_owner_in_zone(name, &zone.name)?;
        if !authorize_prerequisite(&grants, &owner, record_type) {
            return Err(DynamicUpdateError::Refused(format!(
                "TSIG key '{}' is not authorized to read '{}' ({}) in zone '{}'",
                key.name,
                owner,
                record_type.map_or("ANY", RecordType::as_str),
                zone.name
            )));
        }
    }

    for op in updates {
        let owner = parse_owner_in_zone(op.name(), &zone.name)?;
        if !authorize_update(&grants, &owner, op.record_type()) {
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

/// Apply one authorized dynamic update operation in the current transaction.
async fn apply_op_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    op: &UpdateOp,
    new_serial: i32,
) -> Result<bool, DynamicUpdateError> {
    match op {
        UpdateOp::AddRr {
            name,
            record_type,
            value,
            ttl,
            priority,
        } => {
            let owner = parse_owner_in_zone(name, &zone.name)?;

            // Row-encode so nsupdate stores the same spelling as the other write
            // paths; TXT arrives already encoded from the wire rdata.
            let value = if *record_type == RecordType::TXT {
                value.to_string()
            } else {
                record_type.encoded_value(value, *priority).map_err(|e| {
                    DynamicUpdateError::Refused(format!(
                        "invalid {} rdata: {}",
                        record_type.as_str(),
                        e
                    ))
                })?
            };

            let outcome = RecordService::validate_add_tx(
                tx,
                zone,
                &owner,
                record_type,
                &value,
                *ttl,
                *priority,
            )
            .await?;

            // RFC 2136, Section 3.4.2.2: an rdata-identical add is a silent no-op. The
            // TTL-replace clause is not implemented; RRset TTLs change via the API.
            if matches!(outcome, AddOutcome::Duplicate) {
                return Ok(false);
            }

            RecordService::create_with_changes_tx(
                tx,
                zone.id,
                new_serial,
                &[Record {
                    id: 0,
                    name: owner,
                    value,
                    ttl: *ttl,
                    priority: record_type.stored_priority(*priority),
                    record_type: record_type.clone(),
                    zone_id: zone.id,
                    created_at: Utc::now(),
                }],
            )
            .await?;

            Ok(true)
        }
        UpdateOp::DeleteRrset { name, record_type } => {
            delete_matching_tx(tx, zone, name, record_type.as_ref(), None, None, new_serial).await
        }
        UpdateOp::DeleteRr {
            name,
            record_type,
            value,
            priority,
        } => {
            delete_matching_tx(
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

/// Delete every record at `name` matching the given type and (optionally)
/// rdata. `record_type` is `None` for a whole-name delete.
async fn delete_matching_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    name: &str,
    record_type: Option<&RecordType>,
    value: Option<&str>,
    priority: Option<i32>,
    new_serial: i32,
) -> Result<bool, DynamicUpdateError> {
    let owner = parse_owner_in_zone(name, &zone.name)?;
    // Only records at the owner name can match, so lock just those.
    let owner_records =
        RepositoryService::list_records_by_name_tx(tx, zone.id, &owner, LockLevel::Exclusive)
            .await?;

    let matched: Vec<Record> = owner_records
        .iter()
        .filter(|record| matches_record(record, record_type, value, priority))
        .cloned()
        .collect();

    if matched.is_empty() {
        return Ok(false);
    }

    RecordService::delete_with_changes_tx(tx, zone.id, new_serial, &matched).await?;

    Ok(true)
}

/// The owner of an update RR. The wire carries owners absolutely, so a name
/// outside the zone is NOTZONE rather than something to qualify.
fn parse_owner_in_zone(name: &str, zone_name: &ZoneName) -> Result<OwnerName, DynamicUpdateError> {
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
