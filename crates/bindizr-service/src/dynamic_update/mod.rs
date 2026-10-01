//! RFC 2136 dynamic updates, from the point the wire message is decoded.
//! Prerequisite evaluation, per-key authorization, and the transactional apply
//! live here; the DNS front end owns the message format, TSIG, and rdata.

use bindizr_db::LockLevel;

mod prerequisite;
#[cfg(test)]
mod tests;

use bindizr_core::{
    dns::{
        Serial, Ttl,
        name::{OwnerName, ParseNameError, ZoneName, to_fqdn},
    },
    model::record::RecordId,
};
use chrono::Utc;
use prerequisite::evaluate_prerequisites_tx;
use thiserror::Error;

use crate::{
    Context, Transaction, dnssec,
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        tsig_key::TsigKey,
        zone::Zone,
    },
    record::{self, AddResult},
    serial::generate_serial,
    transaction,
    tsig_key::grant::{authorize_prerequisite, authorize_update},
    zone::{self, version::ChangeSubject},
};

/// Why an update was not applied, in the terms RFC 2136, Section 2.2 gives the
/// response code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DynamicUpdateError {
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    YxDomain(String),
    #[error("{0}")]
    YxRrset(String),
    #[error("{0}")]
    NxDomain(String),
    #[error("{0}")]
    NxRrset(String),
    #[error("{0}")]
    NotZone(String),
    #[error("{0}")]
    Internal(String),
}

/// A service error the requester could fix is REFUSED; a backend fault is
/// SERVFAIL.
impl From<ServiceError> for DynamicUpdateError {
    /// Map a service failure to the corresponding dynamic update error.
    fn from(err: ServiceError) -> Self {
        if !err.code().is_internal() {
            DynamicUpdateError::Refused(err.to_string())
        } else {
            DynamicUpdateError::Internal(err.to_string())
        }
    }
}

/// A database failure is a backend fault, classified through the service error.
impl From<bindizr_db::error::DatabaseError> for DynamicUpdateError {
    /// Map a database failure to SERVFAIL.
    fn from(err: bindizr_db::error::DatabaseError) -> Self {
        DynamicUpdateError::from(ServiceError::from(err))
    }
}

/// A condition the zone must satisfy before any update is applied
/// (RFC 2136, Section 2.4). Owner names are absolute, as they arrive on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prerequisite {
    /// CLASS ANY, TYPE ANY: the owner name must exist.
    NameInUse { name: String },
    /// CLASS NONE, TYPE ANY: the owner name must not exist.
    NameNotInUse { name: String },
    /// CLASS ANY: the record set must exist.
    RecordSetInUse {
        name: String,
        record_type: RecordType,
    },
    /// CLASS NONE: the record set must not exist.
    RecordSetNotInUse {
        name: String,
        record_type: RecordType,
    },
    /// CLASS IN: with the others of its name and type, the record set must equal
    /// the zone's (RFC 2136, Section 3.2.3).
    RecordInUse {
        name: String,
        record_type: RecordType,
        /// TXT arrives row-encoded; every other type in presentation form.
        value: String,
        priority: Option<i32>,
    },
}

/// One update to apply (RFC 2136, Section 2.5). Owner names are absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOperation {
    /// CLASS IN: add the record.
    AddRecord {
        name: String,
        record_type: RecordType,
        /// TXT arrives row-encoded; every other type in presentation form.
        value: String,
        ttl: Ttl,
        priority: Option<i32>,
    },
    /// CLASS ANY: delete a record set, or every record set at the owner name when
    /// `record_type` is `None` (wire TYPE ANY).
    DeleteRecordSet {
        name: String,
        record_type: Option<RecordType>,
    },
    /// CLASS NONE: delete the records carrying exactly this rdata.
    DeleteRecord {
        name: String,
        record_type: RecordType,
        value: String,
        priority: Option<i32>,
    },
}

impl UpdateOperation {
    /// Return the owner name targeted by this update operation.
    fn name(&self) -> &str {
        match self {
            UpdateOperation::AddRecord { name, .. }
            | UpdateOperation::DeleteRecordSet { name, .. }
            | UpdateOperation::DeleteRecord { name, .. } => name,
        }
    }

    /// The type this update touches; `None` for a whole-name delete.
    fn record_type(&self) -> Option<&RecordType> {
        match self {
            UpdateOperation::AddRecord { record_type, .. }
            | UpdateOperation::DeleteRecord { record_type, .. } => Some(record_type),
            UpdateOperation::DeleteRecordSet { record_type, .. } => record_type.as_ref(),
        }
    }
}

/// A decoded UPDATE message: the zone it targets, the key that signed it, and
/// the sections to evaluate and apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicUpdate {
    pub zone_name: ZoneName,
    /// The verified signing key, or `None` for a request accepted unsigned.
    pub key: Option<TsigKey>,
    pub prerequisites: Vec<Prerequisite>,
    pub updates: Vec<UpdateOperation>,
}

/// Apply an update as one transaction, reporting whether it changed
/// anything. On a change the zone serial advances once and a NOTIFY is
/// sent after commit.
pub async fn apply(cx: &Context, update: DynamicUpdate) -> Result<bool, DynamicUpdateError> {
    let mut tx = transaction::begin_tx(cx, "failed to begin NSUPDATE transaction").await?;

    let apply_result: Result<(bool, Zone, Serial), DynamicUpdateError> = async {
        let zone = zone::find_served_by_name_tx(&mut tx, &update.zone_name, LockLevel::Exclusive)
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
            dnssec::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            // Bump the serial and version it so secondaries detect the change via
            // SOA/NOTIFY and can serve it as an IXFR delta.
            zone::advance_serial_tx(
                cx,
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
        transaction::finish_tx(tx, apply_result, "failed to commit NSUPDATE transaction").await?;

    if changed {
        log::info!(
            "event=nsupdate_apply zone={} serial={}",
            zone.name,
            new_serial
        );

        // Queue through the service like every other mutation path, so
        // `dns.notify.batch_ms` governs RFC 2136 writes too.
        crate::notify::notify_after_update(cx, &zone.name).await;
    }

    Ok(changed)
}

/// Authorize an authenticated request: global keys may do anything, other
/// keys need a grant reaching every prerequisite and every update record. `key`
/// is `None` for an accepted unsigned request, which skips authorization
/// entirely.
async fn authorize_key_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    key: Option<&TsigKey>,
    prerequisites: &[Prerequisite],
    updates: &[UpdateOperation],
) -> Result<(), DynamicUpdateError> {
    let key = match key {
        None => return Ok(()),
        Some(key) if key.is_global => return Ok(()),
        Some(key) => key,
    };

    // Share-lock the grants so a concurrent revocation waits for this
    // transaction instead of racing it.
    let grants = bindizr_db::tsig_grant::list_by_zone_id_and_key_id_tx(
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
            Prerequisite::RecordSetInUse { name, record_type }
            | Prerequisite::RecordSetNotInUse { name, record_type }
            | Prerequisite::RecordInUse {
                name, record_type, ..
            } => (name, Some(record_type)),
        };
        let owner = parse_update_owner(name, &zone.name)?;
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
        let owner = parse_update_owner(op.name(), &zone.name)?;
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
    tx: &mut Transaction<'_>,
    zone: &Zone,
    op: &UpdateOperation,
    new_serial: Serial,
) -> Result<bool, DynamicUpdateError> {
    match op {
        UpdateOperation::AddRecord {
            name,
            record_type,
            value,
            ttl,
            priority,
        } => {
            let owner = parse_update_owner(name, &zone.name)?;

            // Row-encode so nsupdate stores the same spelling as the other write
            // paths; TXT arrives already encoded from the wire rdata.
            let value = if *record_type == RecordType::Txt {
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

            let outcome =
                record::validate_add_tx(tx, zone, &owner, record_type, &value, *ttl, *priority)
                    .await?;

            // RFC 2136, Section 3.4.2.2: an rdata-identical add is a silent no-op. The
            // TTL-replace clause is not implemented; record set TTLs change via the API.
            if matches!(outcome, AddResult::Duplicate) {
                return Ok(false);
            }

            record::create_with_changes_tx(
                tx,
                zone.id,
                new_serial,
                &[Record {
                    id: RecordId::UNWRITTEN,
                    name: owner,
                    value,
                    ttl: *ttl,
                    priority: record_type.stored_priority(*priority),
                    record_type: *record_type,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                }],
            )
            .await?;

            Ok(true)
        }
        UpdateOperation::DeleteRecordSet { name, record_type } => {
            delete_matching_tx(tx, zone, name, record_type.as_ref(), None, None, new_serial).await
        }
        UpdateOperation::DeleteRecord {
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
    tx: &mut Transaction<'_>,
    zone: &Zone,
    name: &str,
    record_type: Option<&RecordType>,
    value: Option<&str>,
    priority: Option<i32>,
    new_serial: Serial,
) -> Result<bool, DynamicUpdateError> {
    let owner = parse_update_owner(name, &zone.name)?;
    // Only records at the owner name can match, so lock just those.
    let owner_records =
        bindizr_db::record::list_by_name_tx(tx, zone.id, &owner, LockLevel::Exclusive).await?;

    let matched: Vec<Record> = owner_records
        .iter()
        .filter(|record| record.matches(record_type, value, priority))
        .cloned()
        .collect();

    if matched.is_empty() {
        return Ok(false);
    }

    record::delete_with_changes_tx(tx, zone.id, new_serial, &matched).await?;

    Ok(true)
}

/// The owner of an update record. The wire carries owners absolutely, so a name
/// outside the zone is NOTZONE rather than something to qualify.
fn parse_update_owner(name: &str, zone_name: &ZoneName) -> Result<OwnerName, DynamicUpdateError> {
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
