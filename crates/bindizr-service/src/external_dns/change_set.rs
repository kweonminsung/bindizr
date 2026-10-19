//! Turning an ExternalDNS change set into per-zone record operations: parsing
//! the request, grouping it by zone, and computing what each zone must change.

use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};

use bindizr_core::{
    dns::{
        Ttl,
        name::{OwnerName, ZoneName},
    },
    model::record::{RecordId, RecordKey},
};
use chrono::Utc;

use super::policy::{authoritative_zone, normalize_lookup_name};
use crate::{
    authorization::Caller,
    error::ServiceError,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    record::validate_record_constraints,
    ttl::validate_record_ttl,
    types::{ApplyExternalDnsChangesRequest, ExternalDnsRecord},
};

/// Desired records with row-encoded values and an absolute owner before zone resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordSet {
    pub(crate) name: String,
    pub(crate) record_type: RecordType,
    /// Adds only; `None` resolves to the zone TTL at apply time.
    pub(crate) ttl: Option<Ttl>,
    pub(crate) values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordSetOperation {
    pub(crate) record_set: RecordSet,
    pub(crate) is_delete: bool,
}

/// Desired records whose owner is relative to their resolved zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneRecordSet {
    pub(crate) name: OwnerName,
    pub(crate) record_type: RecordType,
    pub(crate) ttl: Option<Ttl>,
    pub(crate) values: Vec<String>,
}

/// Adds and deletes of one request that resolved to the same zone.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ZoneOperations {
    pub(crate) adds: Vec<ZoneRecordSet>,
    pub(crate) deletes: Vec<ZoneRecordSet>,
}

/// The record rows one zone's operations resolve to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ZoneChangeSet {
    pub(crate) deletes: Vec<Record>,
    pub(crate) creates: Vec<Record>,
}

/// Parse a record type the ExternalDNS API manages.
fn parse_supported_record_type(record_type: &str) -> Result<RecordType, ServiceError> {
    RecordType::parse_external_dns_supported(record_type).ok_or_else(|| {
        ServiceError::invalid_input(format!(
            "record type '{}' is not supported by the ExternalDNS API",
            record_type
        ))
    })
}

/// ExternalDNS sends TTL 0 for "not configured"; both resolve to the zone TTL.
fn normalize_ttl(ttl: Option<i64>) -> Result<Option<Ttl>, ServiceError> {
    match ttl {
        Some(0) | None => Ok(None),
        Some(ttl) => Ok(Some(validate_record_ttl(ttl)?)),
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
    if *record_type == RecordType::Cname && record.values.len() > 1 {
        return Err(ServiceError::invalid_record_value(format!(
            "CNAME record '{}' must have exactly one value",
            record.name
        )));
    }
    Ok(())
}

/// Parse and validate an ExternalDNS record group.
pub(crate) fn parse_record_set(record: &ExternalDnsRecord) -> Result<RecordSet, ServiceError> {
    let record_type = parse_supported_record_type(&record.record_type)?;
    let name = normalize_lookup_name(&record.name)?;
    let ttl = normalize_ttl(record.ttl)?;
    validate_record_set_shape(record, &record_type)?;

    // Deduplicate values that normalize identically (e.g. IPv6 spellings).
    let mut seen = HashSet::new();
    let mut values: Vec<String> = Vec::new();
    for value in &record.values {
        let encoded = record_type
            .encoded_value(value, None)
            .map_err(ServiceError::invalid_record_value)?;
        if seen.insert(record_type.canonical_value(&encoded, None).into_owned()) {
            values.push(encoded);
        }
    }

    Ok(RecordSet {
        name,
        record_type,
        ttl,
        values,
    })
}

/// Canonicalize a desired record for apply/list, preserving the submitted name.
/// Leave invalid values for apply to report through its normal validation.
pub(crate) fn adjust_record_set(
    record: &ExternalDnsRecord,
) -> Result<ExternalDnsRecord, ServiceError> {
    let record_type = parse_supported_record_type(&record.record_type)?;
    let ttl = normalize_ttl(record.ttl)?;
    validate_record_set_shape(record, &record_type)?;

    let mut values: Vec<String> = record
        .values
        .iter()
        .map(|value| match record_type.encoded_value(value, None) {
            Ok(encoded) => record_type.presentation_rdata(&encoded, None),
            Err(_) => value.clone(),
        })
        .collect();
    // The answer is sorted anyway, which puts duplicates side by side.
    values.sort();
    values.dedup();

    Ok(ExternalDnsRecord {
        name: record.name.clone(),
        record_type: record_type.to_string(),
        ttl: ttl.map(i64::from),
        values,
    })
}

/// Flatten the request into ordered operations; an update becomes
/// delete(old) + add(new), with unchanged pairs canceling later.
pub(crate) fn parse_changes_request(
    request: &ApplyExternalDnsChangesRequest,
) -> Result<Vec<RecordSetOperation>, ServiceError> {
    let mut operations = Vec::new();
    for record_set in &request.deletes {
        operations.push(RecordSetOperation {
            record_set: parse_record_set(record_set)?,
            is_delete: true,
        });
    }
    for update in &request.updates {
        operations.push(RecordSetOperation {
            record_set: parse_record_set(&update.old)?,
            is_delete: true,
        });
        operations.push(RecordSetOperation {
            record_set: parse_record_set(&update.new)?,
            is_delete: false,
        });
    }
    for record_set in &request.creates {
        operations.push(RecordSetOperation {
            record_set: parse_record_set(record_set)?,
            is_delete: false,
        });
    }
    Ok(operations)
}

/// Resolve every operation to its most-specific authoritative zone; the
/// caller's write authorization is checked per zone inside the transaction.
pub(crate) fn group_operations_by_zone(
    caller: &Caller,
    zones: &[Zone],
    operations: Vec<RecordSetOperation>,
) -> Result<BTreeMap<ZoneName, ZoneOperations>, ServiceError> {
    let mut grouped: BTreeMap<ZoneName, ZoneOperations> = BTreeMap::new();

    for pending in operations {
        // From all zones, so a hidden subzone still shadows a granted parent.
        let (zone, name) = authoritative_zone(zones, &pending.record_set.name)
            .filter(|(zone, _)| caller.sees_zone(zone.id))
            .ok_or_else(|| {
                ServiceError::ZoneNotFound(format!(
                    "no zone is authoritative for '{}'",
                    pending.record_set.name
                ))
            })?;

        let record_set = ZoneRecordSet {
            name,
            record_type: pending.record_set.record_type,
            ttl: pending.record_set.ttl,
            values: pending.record_set.values,
        };
        let entry = grouped.entry(zone.name.clone()).or_default();
        if pending.is_delete {
            entry.deletes.push(record_set);
        } else {
            entry.adds.push(record_set);
        }
    }

    Ok(grouped)
}

impl ZoneChangeSet {
    /// Resolve one zone's operations against its current records; idempotent
    /// operations cancel out, so an effect-free request yields an empty set.
    pub(crate) fn compute(
        operations: &ZoneOperations,
        zone: &Zone,
        existing: &[Record],
    ) -> Result<Self, ServiceError> {
        let mut existing_by_key: HashMap<RecordKey, Vec<&Record>> = HashMap::new();
        for row in existing {
            existing_by_key
                .entry(row.match_key())
                .or_default()
                .push(row);
        }

        // A cancelled delete leaves a hole, so a later add sees its row as surviving.
        let mut deletes: Vec<Option<Record>> = Vec::new();
        let mut delete_slots: HashMap<RecordId, usize> = HashMap::new();
        for del in &operations.deletes {
            for value in &del.values {
                let key = RecordKey::new(&del.name, del.record_type, value, None);
                for row in existing_by_key.get(&key).into_iter().flatten() {
                    if let Entry::Vacant(slot) = delete_slots.entry(row.id) {
                        slot.insert(deletes.len());
                        deletes.push(Some((*row).clone()));
                    }
                }
            }
        }

        let mut creates: Vec<Record> = Vec::new();
        let mut created: HashSet<(RecordKey, Ttl)> = HashSet::new();
        for add in &operations.adds {
            let ttl = add.ttl.unwrap_or(zone.default_ttl);
            for value in &add.values {
                let key = RecordKey::new(&add.name, add.record_type, value, None);
                let rows: &[&Record] = existing_by_key.get(&key).map_or(&[], Vec::as_slice);

                // An unchanged update cancels its own delete instead of rewriting
                // the row. TTL-sensitive, so a TTL-only update is still a change.
                if let Some(slot) = rows
                    .iter()
                    .filter(|row| row.ttl == ttl)
                    .find_map(|row| delete_slots.remove(&row.id))
                {
                    deletes[slot] = None;
                    continue;
                }
                // Idempotent create: a surviving row already holds this rdata. TTL
                // is excluded to match the duplicate check behind this one, which
                // would otherwise reject the create as a conflict.
                if rows.iter().any(|row| !delete_slots.contains_key(&row.id)) {
                    continue;
                }
                if !created.insert((key, ttl)) {
                    continue;
                }

                creates.push(Record {
                    id: RecordId::UNWRITTEN,
                    name: add.name.clone(),
                    record_type: add.record_type,
                    value: value.clone(),
                    ttl,
                    priority: None,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                });
            }
        }
        let deletes: Vec<Record> = deletes.into_iter().flatten().collect();

        // Validate each insert against the post-delete state plus earlier inserts,
        // so CNAME exclusivity and record set TTL rules see the state they will land in.
        let deleted_ids: HashSet<RecordId> = deletes.iter().map(|d| d.id).collect();
        let mut simulated_by_name: HashMap<OwnerName, Vec<Record>> = HashMap::new();
        for row in existing {
            if !deleted_ids.contains(&row.id) {
                simulated_by_name
                    .entry(row.name.clone())
                    .or_default()
                    .push(row.clone());
            }
        }
        for create in &creates {
            let records_at_name = simulated_by_name.entry(create.name.clone()).or_default();
            validate_record_constraints(
                records_at_name,
                &create.name,
                &create.record_type,
                &create.value,
                create.ttl,
                create.priority,
                None,
            )?;
            records_at_name.push(create.clone());
        }

        Ok(ZoneChangeSet { deletes, creates })
    }
}
