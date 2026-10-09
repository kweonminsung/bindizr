//! The update section of RFC 2136, Section 2.5: each operation as decoded,
//! and its application to the locked zone.

use bindizr_core::{
    dns::{Serial, Ttl},
    model::{record::RecordId, role_grant::Action},
};
use bindizr_db::LockLevel;
use chrono::Utc;

use super::{NsupdateError, parse_update_owner};
use crate::{
    Transaction,
    authorization::{Caller, RecordAccess},
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    record::{self, AddResult},
};

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
    /// The grant action this operation needs: an add creates, both deletes delete.
    pub(crate) fn action(&self) -> Action {
        match self {
            UpdateOperation::AddRecord { .. } => Action::RecordCreate,
            UpdateOperation::DeleteRecordSet { .. } | UpdateOperation::DeleteRecord { .. } => {
                Action::RecordDelete
            }
        }
    }

    /// Return the owner name targeted by this update operation.
    pub(crate) fn name(&self) -> &str {
        match self {
            UpdateOperation::AddRecord { name, .. }
            | UpdateOperation::DeleteRecordSet { name, .. }
            | UpdateOperation::DeleteRecord { name, .. } => name,
        }
    }

    /// The type this update touches; `None` for a whole-name delete.
    pub(crate) fn record_type(&self) -> Option<&RecordType> {
        match self {
            UpdateOperation::AddRecord { record_type, .. }
            | UpdateOperation::DeleteRecord { record_type, .. } => Some(record_type),
            UpdateOperation::DeleteRecordSet { record_type, .. } => record_type.as_ref(),
        }
    }
}

/// Apply one authorized nsupdate operation in the current transaction.
pub(crate) async fn apply_op_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    op: &UpdateOperation,
    new_serial: Serial,
    caller: &Caller,
) -> Result<bool, NsupdateError> {
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
                    NsupdateError::Refused(format!("invalid {} rdata: {}", record_type.as_str(), e))
                })?
            };

            let records_at_name =
                bindizr_db::record::list_by_name_tx(tx, zone.id, &owner, LockLevel::Exclusive)
                    .await?;

            // RFC 2136, Section 3.4.2.2: a CNAME beside other data (the apex
            // holds the SOA) or data beside a CNAME is ignored.
            let adding_cname = *record_type == RecordType::Cname;
            let has_cname = records_at_name
                .iter()
                .any(|r| r.record_type == RecordType::Cname);
            let has_other = records_at_name
                .iter()
                .any(|r| r.record_type != RecordType::Cname);
            if (adding_cname && (owner.is_apex() || has_other)) || (!adding_cname && has_cname) {
                return Ok(false);
            }

            // RFC 2136, Section 3.4.2.2 and RFC 6672, Section 5.2: a second
            // CNAME or DNAME with other rdata replaces the first.
            let is_alias = matches!(record_type, RecordType::Cname | RecordType::Dname);
            let replaced: Vec<Record> = records_at_name
                .iter()
                .filter(|r| {
                    is_alias && r.record_type == *record_type && !r.has_rdata(&value, *priority)
                })
                .cloned()
                .collect();
            let mut changed = false;
            if !replaced.is_empty() {
                // Replacing deletes what stood there; the create grant alone
                // does not reach it.
                caller.authorize_record_access(
                    zone,
                    &[RecordAccess {
                        action: Action::RecordDelete,
                        relative_name: owner.clone(),
                        record_type: Some(record_type),
                    }],
                )?;
                record::delete_with_changes_tx(tx, zone.id, new_serial, &replaced).await?;
                changed = true;
            }

            // RFC 2136, Section 3.4.2.2 and RFC 2181, Section 5.2: an add with
            // a new TTL moves the rest of the record set to it, as a delete and
            // an add.
            let retimed: Vec<Record> = records_at_name
                .iter()
                .filter(|r| {
                    r.record_type == *record_type
                        && r.ttl != *ttl
                        && !replaced.iter().any(|gone| gone.id == r.id)
                })
                .cloned()
                .collect();
            if !retimed.is_empty() {
                // Retiming rewrites the set that stood there: an update.
                caller.authorize_record_access(
                    zone,
                    &[RecordAccess {
                        action: Action::RecordUpdate,
                        relative_name: owner.clone(),
                        record_type: Some(record_type),
                    }],
                )?;
                record::delete_with_changes_tx(tx, zone.id, new_serial, &retimed).await?;
                let renewed: Vec<Record> = retimed
                    .into_iter()
                    .map(|record| Record {
                        id: RecordId::UNWRITTEN,
                        ttl: *ttl,
                        created_at: Utc::now(),
                        ..record
                    })
                    .collect();
                record::create_with_changes_tx(tx, zone.id, new_serial, &renewed).await?;
                changed = true;
            }

            let outcome =
                record::validate_add_tx(tx, zone, &owner, record_type, &value, *ttl, *priority)
                    .await?;

            // An rdata-identical add changes nothing beyond the TTL above.
            if matches!(outcome, AddResult::Duplicate) {
                return Ok(changed);
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
) -> Result<bool, NsupdateError> {
    let owner = parse_update_owner(name, &zone.name)?;
    // Only records at the owner name can match, so lock just those.
    let owner_records =
        bindizr_db::record::list_by_name_tx(tx, zone.id, &owner, LockLevel::Exclusive).await?;

    let mut matched: Vec<Record> = owner_records
        .iter()
        .filter(|record| record.matches(record_type, value, priority))
        .cloned()
        .collect();

    // RFC 2136, Sections 3.4.2.3 and 3.4.2.4: at the apex the NS set outlives
    // a delete, and one NS goes only while another remains; the SOA is no row.
    if owner.is_apex() {
        let ns_total = owner_records
            .iter()
            .filter(|r| r.record_type == RecordType::Ns)
            .count();
        match value {
            None => matched.retain(|r| r.record_type != RecordType::Ns),
            Some(_) if ns_total <= 1 => matched.retain(|r| r.record_type != RecordType::Ns),
            Some(_) => {}
        }
    }

    if matched.is_empty() {
        return Ok(false);
    }

    record::delete_with_changes_tx(tx, zone.id, new_serial, &matched).await?;

    Ok(true)
}
