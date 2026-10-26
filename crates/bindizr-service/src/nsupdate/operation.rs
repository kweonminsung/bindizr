//! The update section of RFC 2136, Section 2.5: each operation as decoded,
//! and its application to the locked zone.

use bindizr_core::dns::name::OwnerName;
use bindizr_core::dns::{Serial, Ttl};
use bindizr_core::model::record::RecordId;
use bindizr_core::model::role_grant::Action;
use bindizr_db::LockLevel;
use chrono::Utc;

use super::NsupdateError;
use crate::Transaction;
use crate::authorization::{Caller, RecordAccess};
use crate::model::record::{Record, RecordType};
use crate::model::zone::Zone;
use crate::record::{self, AddResult};

/// One update to apply (RFC 2136, Section 2.5). Owner names have passed the zone prescan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordOperation {
    /// CLASS IN: add the record.
    AddRecord {
        name: OwnerName,
        record_type: RecordType,
        /// TXT arrives row-encoded; every other type in presentation form.
        value: String,
        ttl: Ttl,
        priority: Option<i32>,
    },
    /// CLASS ANY: delete a record set, or every record set at the owner name when
    /// `record_type` is `None` (wire TYPE ANY).
    DeleteRecordSet {
        name: OwnerName,
        record_type: Option<RecordType>,
    },
    /// CLASS NONE: delete the records carrying exactly this rdata.
    DeleteRecord {
        name: OwnerName,
        record_type: RecordType,
        value: String,
        priority: Option<i32>,
    },
}

impl RecordOperation {
    /// The grant action this operation needs: an add creates, both deletes delete.
    pub(crate) fn action(&self) -> Action {
        match self {
            RecordOperation::AddRecord { .. } => Action::RecordCreate,
            RecordOperation::DeleteRecordSet { .. } | RecordOperation::DeleteRecord { .. } => {
                Action::RecordDelete
            }
        }
    }

    /// Return the owner name targeted by this update operation.
    pub(crate) fn name(&self) -> &OwnerName {
        match self {
            RecordOperation::AddRecord { name, .. }
            | RecordOperation::DeleteRecordSet { name, .. }
            | RecordOperation::DeleteRecord { name, .. } => name,
        }
    }

    /// The type this update touches; `None` for a whole-name delete.
    pub(crate) fn record_type(&self) -> Option<&RecordType> {
        match self {
            RecordOperation::AddRecord { record_type, .. }
            | RecordOperation::DeleteRecord { record_type, .. } => Some(record_type),
            RecordOperation::DeleteRecordSet { record_type, .. } => record_type.as_ref(),
        }
    }
}

/// Apply one authorized nsupdate operation in the current transaction.
pub(crate) async fn apply_record_operation_tx(
    tx: &mut Transaction<'_>,
    caller: &Caller,
    zone: &Zone,
    operation: &RecordOperation,
    new_serial: Serial,
) -> Result<bool, NsupdateError> {
    match operation {
        RecordOperation::AddRecord {
            name: owner,
            record_type,
            value,
            ttl,
            priority,
        } => {
            // Row-encode so nsupdate stores the same spelling as the other write
            // paths; TXT arrives already encoded from the wire rdata.
            let value = if *record_type == RecordType::Txt {
                value.to_string()
            } else {
                record_type
                    .encoded_value(value, *priority)
                    .map_err(|source| NsupdateError::RecordValue {
                        record_type: *record_type,
                        source,
                    })?
            };

            let records_at_name =
                bindizr_db::record::list_by_name_tx(tx, zone.id, owner, LockLevel::Exclusive)
                    .await?;

            // RFC 2136, Section 3.4.2.2: a CNAME beside other data (the apex
            // holds the SOA) or data beside a CNAME is ignored.
            let adding_cname = *record_type == RecordType::Cname;
            let has_cname = records_at_name
                .iter()
                .any(|record| record.record_type == RecordType::Cname);
            let has_other = records_at_name
                .iter()
                .any(|record| record.record_type != RecordType::Cname);

            if (adding_cname && (owner.is_apex() || has_other)) || (!adding_cname && has_cname) {
                return Ok(false);
            }

            // RFC 2136, Section 3.4.2.2 and RFC 6672, Section 5.2: a second
            // CNAME or DNAME replaces the first; WKS replaces its address/protocol match.
            let replaced: Vec<Record> = records_at_name
                .iter()
                .filter(|record| {
                    record.record_type == *record_type && record.is_replaced_by(&value, *priority)
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

            // RFC 2136, Section 3.4.2.2 and RFC 2181, Section 5.2:
            // retime the name/type's records through delete/add journal changes.
            let retimed: Vec<Record> = records_at_name
                .iter()
                .filter(|record| {
                    record.record_type == *record_type
                        && record.ttl != *ttl
                        && !replaced.iter().any(|gone| gone.id == record.id)
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
                record::validate_add_tx(tx, zone, owner, record_type, &value, *ttl, *priority)
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
                    name: owner.clone(),
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
        RecordOperation::DeleteRecordSet { name, record_type } => {
            delete_matching_tx(tx, zone, name, record_type.as_ref(), None, None, new_serial).await
        }
        RecordOperation::DeleteRecord {
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

/// Delete every record at `owner` matching the given type and (optionally)
/// rdata. `record_type` is `None` for a whole-name delete.
async fn delete_matching_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    owner: &OwnerName,
    record_type: Option<&RecordType>,
    value: Option<&str>,
    priority: Option<i32>,
    new_serial: Serial,
) -> Result<bool, NsupdateError> {
    // Only records at the owner name can match, so lock just those.
    let owner_records =
        bindizr_db::record::list_by_name_tx(tx, zone.id, owner, LockLevel::Exclusive).await?;

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
            .filter(|record| record.record_type == RecordType::Ns)
            .count();

        match value {
            None => matched.retain(|record| record.record_type != RecordType::Ns),
            Some(_) if ns_total <= 1 => {
                matched.retain(|record| record.record_type != RecordType::Ns)
            }
            Some(_) => {}
        }
    }

    if matched.is_empty() {
        return Ok(false);
    }

    record::delete_with_changes_tx(tx, zone.id, new_serial, &matched).await?;

    Ok(true)
}
