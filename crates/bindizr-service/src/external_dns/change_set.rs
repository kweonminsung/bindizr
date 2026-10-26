//! Turning an ExternalDNS change set into per-zone record operations: parsing
//! the request, grouping it by zone, and computing what each zone must change.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};

use bindizr_core::dns::Ttl;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::model::record::{RecordId, RecordKey};
use chrono::Utc;

use super::policy;
use crate::error::ServiceError;
use crate::model::record::{Record, RecordType};
use crate::model::zone::Zone;
use crate::types::{ApplyExternalDnsChangesRequest, ExternalDnsRecord};
use crate::{record, ttl};

/// Desired records with row-encoded values and an absolute owner before zone resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordSet {
    pub(crate) name: String,
    pub(crate) record_type: RecordType,
    /// Adds only; `None` resolves to the zone TTL at apply time.
    pub(crate) ttl: Option<Ttl>,
    pub(crate) values: Vec<String>,
}

/// An ordered addition or deletion before its authoritative zone is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordSetOperation {
    Add(RecordSet),
    Delete(RecordSet),
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
    /// The first requested absolute name, for refusals that must not name a hidden zone.
    pub(crate) request_name: String,
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
        Some(ttl) => Ok(Some(ttl::validate_record_ttl(ttl)?)),
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
    let name = policy::normalize_lookup_name(&record.name)?;
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
        operations.push(RecordSetOperation::Delete(parse_record_set(record_set)?));
    }

    for update in &request.updates {
        operations.push(RecordSetOperation::Delete(parse_record_set(&update.old)?));
        operations.push(RecordSetOperation::Add(parse_record_set(&update.new)?));
    }

    for record_set in &request.creates {
        operations.push(RecordSetOperation::Add(parse_record_set(record_set)?));
    }

    Ok(operations)
}

/// Group operations by their most-specific authoritative zone, independently of grants.
pub(crate) fn group_operations_by_zone(
    zones: &[Zone],
    operations: Vec<RecordSetOperation>,
) -> Result<BTreeMap<ZoneName, ZoneOperations>, ServiceError> {
    let mut grouped: BTreeMap<ZoneName, ZoneOperations> = BTreeMap::new();

    for pending in operations {
        let (RecordSetOperation::Add(record_set) | RecordSetOperation::Delete(record_set)) =
            &pending;
        // From all zones, so a hidden subzone still shadows a granted parent.
        let (zone, name) =
            policy::authoritative_zone(zones, &record_set.name).ok_or_else(|| {
                ServiceError::ZoneNotFound(format!(
                    "no zone is authoritative for '{}'",
                    record_set.name
                ))
            })?;

        let entry = grouped
            .entry(zone.name.clone())
            .or_insert_with(|| ZoneOperations {
                request_name: record_set.name.clone(),
                ..Default::default()
            });

        let (destination, record_set) = match pending {
            RecordSetOperation::Delete(record_set) => (&mut entry.deletes, record_set),
            RecordSetOperation::Add(record_set) => (&mut entry.adds, record_set),
        };
        destination.push(ZoneRecordSet {
            name,
            record_type: record_set.record_type,
            ttl: record_set.ttl,
            values: record_set.values,
        });
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

        for record in existing {
            existing_by_key
                .entry(record.match_key())
                .or_default()
                .push(record);
        }

        // A cancelled delete leaves a hole, so a later add sees its row as surviving.
        let mut deletes: Vec<Option<Record>> = Vec::new();
        let mut delete_slots: HashMap<RecordId, usize> = HashMap::new();

        for record_set in &operations.deletes {
            for value in &record_set.values {
                let key = RecordKey::new(&record_set.name, record_set.record_type, value, None);

                for record in existing_by_key.get(&key).into_iter().flatten() {
                    if let Entry::Vacant(slot) = delete_slots.entry(record.id) {
                        slot.insert(deletes.len());
                        deletes.push(Some((*record).clone()));
                    }
                }
            }
        }

        let mut creates: Vec<Record> = Vec::new();
        let mut created: HashSet<(RecordKey, Ttl)> = HashSet::new();

        for record_set in &operations.adds {
            let ttl = record_set.ttl.unwrap_or(zone.default_ttl);

            for value in &record_set.values {
                let key = RecordKey::new(&record_set.name, record_set.record_type, value, None);
                let records: &[&Record] = existing_by_key.get(&key).map_or(&[], Vec::as_slice);

                // An unchanged update cancels its own delete instead of rewriting
                // the row. TTL-sensitive, so a TTL-only update is still a change.
                if let Some(slot) = records
                    .iter()
                    .filter(|record| record.ttl == ttl)
                    .find_map(|record| delete_slots.remove(&record.id))
                {
                    deletes[slot] = None;
                    continue;
                }

                // Idempotent create: a surviving row already holds this rdata. TTL
                // is excluded to match the duplicate check behind this one, which
                // would otherwise reject the create as a conflict.
                if records
                    .iter()
                    .any(|record| !delete_slots.contains_key(&record.id))
                {
                    continue;
                }
                if !created.insert((key, ttl)) {
                    continue;
                }

                creates.push(Record {
                    id: RecordId::UNWRITTEN,
                    name: record_set.name.clone(),
                    record_type: record_set.record_type,
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
        let deleted_ids: HashSet<RecordId> = deletes.iter().map(|record| record.id).collect();
        let mut simulated_by_name: HashMap<OwnerName, Vec<Record>> = HashMap::new();

        for record in existing {
            if !deleted_ids.contains(&record.id) {
                simulated_by_name
                    .entry(record.name.clone())
                    .or_default()
                    .push(record.clone());
            }
        }

        for record in &creates {
            let records_at_name = simulated_by_name.entry(record.name.clone()).or_default();
            record::validate_record_constraints(
                records_at_name,
                &record.name,
                &record.record_type,
                &record.value,
                record.ttl,
                record.priority,
                None,
            )?;
            records_at_name.push(record.clone());
        }

        Ok(ZoneChangeSet { deletes, creates })
    }
}
