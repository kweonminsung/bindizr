//! Turning an ExternalDNS change set into per-zone record operations: parsing
//! the request, grouping it by zone, and computing what each zone must change.

use std::collections::BTreeMap;

use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::policy::{authoritative_zone, normalize_lookup_name};
use crate::{
    authorization::Caller,
    error::{ErrorCode, ServiceError},
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    record::{parse_record_type, validate_record_add_constraints_normalized, validate_record_ttl},
    types::{ExternalDnsChangesRequest, ExternalDnsRecord},
};

/// One desired RRset operation as the request spells it: values are
/// row-encoded, but the owner is still an absolute lookup name with no zone
/// resolved yet.
#[derive(Debug)]
pub(crate) struct RecordSetOp {
    pub(crate) name: String,
    pub(crate) record_type: RecordType,
    /// Adds only; `None` resolves to the zone TTL at apply time.
    pub(crate) ttl: Option<i32>,
    pub(crate) values: Vec<String>,
}

pub(crate) struct PendingOp {
    pub(crate) op: RecordSetOp,
    pub(crate) is_delete: bool,
}

/// The same operation once grouping has decided which zone owns it, so the
/// owner is relative to that zone.
#[derive(Debug)]
pub(crate) struct ZoneRecordSetOp {
    pub(crate) name: OwnerName,
    pub(crate) record_type: RecordType,
    pub(crate) ttl: Option<i32>,
    pub(crate) values: Vec<String>,
}

/// Adds and deletes of one request that resolved to the same zone.
#[derive(Debug, Default)]
pub(crate) struct ZoneOps {
    pub(crate) adds: Vec<ZoneRecordSetOp>,
    pub(crate) dels: Vec<ZoneRecordSetOp>,
}

/// The record rows one zone's operations resolve to.
#[derive(Debug, Default)]
pub(crate) struct ZoneChangeSet {
    pub(crate) deletes: Vec<Record>,
    pub(crate) creates: Vec<Record>,
}

/// Parse a record type supported by the external-dns adapter.
fn parse_supported_record_type(record_type: &str) -> Result<RecordType, ServiceError> {
    let parsed = parse_record_type(record_type)?;
    if !parsed.is_external_dns_supported() {
        return Err(ServiceError::invalid_input(format!(
            "record type '{}' is not supported by the ExternalDNS API",
            parsed
        )));
    }
    Ok(parsed)
}

/// ExternalDNS sends TTL 0 for "not configured"; both resolve to the zone TTL.
fn normalize_ttl(ttl: Option<i32>) -> Result<Option<i32>, ServiceError> {
    match ttl {
        Some(0) | None => Ok(None),
        Some(ttl) => {
            validate_record_ttl(ttl)?;
            Ok(Some(ttl))
        }
    }
}

/// Require nonempty values and exactly one value for a CNAME group.
fn validate_record_set_shape(
    record: &ExternalDnsRecord,
    record_type: &RecordType,
) -> Result<(), ServiceError> {
    if record.values.is_empty() {
        return Err(ServiceError::invalid_input(format!(
            "record '{}' {} must have at least one value",
            record.name, record_type
        )));
    }
    if *record_type == RecordType::CNAME && record.values.len() > 1 {
        return Err(ServiceError::invalid_record_value(format!(
            "CNAME record '{}' must have exactly one value",
            record.name
        )));
    }
    Ok(())
}

/// Convert an external-dns record group into a validated change operation.
pub(crate) fn parse_record_set_op(record: &ExternalDnsRecord) -> Result<RecordSetOp, ServiceError> {
    let record_type = parse_supported_record_type(&record.record_type)?;
    let name = normalize_lookup_name(&record.name)?;
    let ttl = normalize_ttl(record.ttl)?;
    validate_record_set_shape(record, &record_type)?;

    // Deduplicate values that normalize identically (e.g. IPv6 spellings).
    let mut values: Vec<String> = Vec::with_capacity(record.values.len());
    for value in &record.values {
        let encoded = record_type
            .encoded_value(value, None)
            .map_err(ServiceError::invalid_record_value)?;
        if !values
            .iter()
            .any(|existing| record_type.values_equal(existing, None, &encoded, None))
        {
            values.push(encoded);
        }
    }

    Ok(RecordSetOp {
        name,
        record_type,
        ttl,
        values,
    })
}

/// One record in the canonical form `apply_changes` would store and
/// `list_records` return. Unparseable values pass through so apply reports
/// its ordinary error; the name is echoed as sent.
pub(crate) fn adjust_record_set(
    record: &ExternalDnsRecord,
) -> Result<ExternalDnsRecord, ServiceError> {
    let record_type = parse_supported_record_type(&record.record_type)?;
    let ttl = normalize_ttl(record.ttl)?;
    validate_record_set_shape(record, &record_type)?;

    let mut values: Vec<String> = Vec::with_capacity(record.values.len());
    for value in &record.values {
        let canonical = match record_type.encoded_value(value, None) {
            Ok(encoded) => record_type.presentation_rdata(&encoded, None),
            Err(_) => value.clone(),
        };
        if !values.contains(&canonical) {
            values.push(canonical);
        }
    }
    values.sort();

    Ok(ExternalDnsRecord {
        name: record.name.clone(),
        record_type: record_type.to_string(),
        ttl,
        values,
    })
}

/// Flatten the request into ordered operations; an update becomes
/// delete(old) + add(new), with unchanged pairs canceling later.
pub(crate) fn parse_changes_request(
    request: &ExternalDnsChangesRequest,
) -> Result<Vec<PendingOp>, ServiceError> {
    let mut ops = Vec::new();
    for record_set in &request.deletes {
        ops.push(PendingOp {
            op: parse_record_set_op(record_set)?,
            is_delete: true,
        });
    }
    for update in &request.updates {
        ops.push(PendingOp {
            op: parse_record_set_op(&update.old)?,
            is_delete: true,
        });
        ops.push(PendingOp {
            op: parse_record_set_op(&update.new)?,
            is_delete: false,
        });
    }
    for record_set in &request.creates {
        ops.push(PendingOp {
            op: parse_record_set_op(record_set)?,
            is_delete: false,
        });
    }
    Ok(ops)
}

/// Resolve every operation to its most-specific authoritative zone; the
/// caller's write authorization is checked per zone inside the transaction.
pub(crate) fn group_ops_by_zone(
    caller: &Caller,
    zones: &[Zone],
    ops: Vec<PendingOp>,
) -> Result<BTreeMap<ZoneName, ZoneOps>, ServiceError> {
    let mut grouped: BTreeMap<ZoneName, ZoneOps> = BTreeMap::new();

    for pending in ops {
        // From every zone, so a hidden subzone still shadows a granted parent.
        let zone = authoritative_zone(zones, &pending.op.name)
            .filter(|zone| caller.sees_zone(zone.id))
            .ok_or_else(|| {
                ServiceError::new(
                    ErrorCode::ZoneNotFound,
                    format!("No zone is authoritative for '{}'", pending.op.name),
                )
            })?;

        let op = ZoneRecordSetOp {
            name: OwnerName::parse_absolute_in_zone(&pending.op.name, &zone.name)
                .expect("authoritative_zone matched the name inside this zone"),
            record_type: pending.op.record_type,
            ttl: pending.op.ttl,
            values: pending.op.values,
        };
        let entry = grouped.entry(zone.name.clone()).or_default();
        if pending.is_delete {
            entry.dels.push(op);
        } else {
            entry.adds.push(op);
        }
    }

    Ok(grouped)
}

impl ZoneOps {
    /// Resolve one zone's operations against its current records; idempotent
    /// operations cancel out, so an effect-free request yields an empty set.
    pub(crate) fn compute_change_set(
        &self,
        zone: &Zone,
        existing: &[Record],
    ) -> Result<ZoneChangeSet, ServiceError> {
        let mut deletes: Vec<Record> = Vec::new();
        for del in &self.dels {
            for value in &del.values {
                for row in existing {
                    if row.name == del.name
                        && row.record_type == del.record_type
                        && row.has_rdata(value, None)
                        && !deletes.iter().any(|d| d.id == row.id)
                    {
                        deletes.push(row.clone());
                    }
                }
            }
        }

        let mut creates: Vec<Record> = Vec::new();
        for add in &self.adds {
            let ttl = add.ttl.unwrap_or(zone.default_ttl);
            for value in &add.values {
                let same_rdata = |record: &Record| {
                    record.name == add.name
                        && record.record_type == add.record_type
                        && record.has_rdata(value, None)
                };
                let matches = |record: &Record| same_rdata(record) && record.ttl == ttl;

                // An unchanged update cancels its own delete instead of rewriting
                // the row. TTL-sensitive, so a TTL-only update is still a change.
                if let Some(pos) = deletes.iter().position(&matches) {
                    deletes.remove(pos);
                    continue;
                }
                // Idempotent create: a surviving row already holds this rdata. TTL
                // is excluded to match the duplicate check behind this one, which
                // would otherwise reject the create as a conflict.
                if existing
                    .iter()
                    .any(|row| deletes.iter().all(|d| d.id != row.id) && same_rdata(row))
                {
                    continue;
                }
                if creates.iter().any(matches) {
                    continue;
                }

                creates.push(Record {
                    id: 0,
                    name: add.name.clone(),
                    record_type: add.record_type.clone(),
                    value: value.clone(),
                    ttl,
                    priority: None,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                });
            }
        }

        // Validate each insert against the post-delete state plus earlier inserts,
        // so CNAME exclusivity and RRset TTL rules see the state they will land in.
        for (index, create) in creates.iter().enumerate() {
            let mut records_at_name: Vec<Record> = existing
                .iter()
                .filter(|row| deletes.iter().all(|d| d.id != row.id) && row.name == create.name)
                .cloned()
                .collect();
            records_at_name.extend(
                creates[..index]
                    .iter()
                    .filter(|row| row.name == create.name)
                    .cloned(),
            );

            validate_record_add_constraints_normalized(
                &records_at_name,
                &create.name,
                &create.record_type,
                &create.value,
                create.ttl,
                create.priority,
                None,
            )?;
        }

        Ok(ZoneChangeSet { deletes, creates })
    }
}
