//! Reconcile imported records and build their preview without writing rows.

use std::collections::{HashMap, HashSet};

use bindizr_core::dns::name::OwnerName;

use crate::{
    model::{record::Record, zone::Zone},
    record::{bulk::PreparedRecord, validation::validate_delete_constraints},
    types::{ImportMode, RecordDiff},
    zone::{diff::build_record_diff, history::ReconstructedRecord},
};

/// A record the import wants present, with its owner name already normalized so
/// it can be compared against existing records.
pub(crate) struct DesiredRecord {
    pub(crate) prepared: PreparedRecord,
    pub(crate) stored_name: OwnerName,
}

impl DesiredRecord {
    /// Whether `existing` has the desired identity; TTL is reconciled separately.
    fn matches(&self, existing: &Record) -> bool {
        let record_type = &self.prepared.record_type;
        existing.name == self.stored_name
            && existing.record_type == *record_type
            && record_type.values_equal(
                &existing.value,
                existing.priority,
                &self.prepared.value,
                self.prepared.priority,
            )
    }
}

/// Records referenced by the zone's own SOA/mname NS must never be removed.
fn is_protected(zone: &Zone, record: &Record) -> bool {
    validate_delete_constraints(zone, std::slice::from_ref(record)).is_err()
}

/// What an import will change, decided before anything is written.
pub(crate) struct ImportPlan<'a> {
    pub(crate) dels: Vec<Record>,
    /// Reinserted through `adds`; kept apart so the summary counts them as updates.
    pub(crate) ttl_dels: Vec<Record>,
    pub(crate) adds: Vec<&'a DesiredRecord>,
    pub(crate) unchanged: usize,
    pub(crate) updated: usize,
}

/// Reconcile the file against the zone under `mode`. Records are indexed by
/// owner name so each one is compared only against same-name rows, and a
/// record the zone's own SOA or apex NS depends on is never deleted.
pub(crate) fn compute_import_plan<'a>(
    mode: ImportMode,
    zone: &Zone,
    existing_records: &[Record],
    desired: &'a [DesiredRecord],
) -> ImportPlan<'a> {
    let mut existing_by_name: HashMap<&OwnerName, Vec<&Record>> =
        HashMap::with_capacity(existing_records.len());
    for record in existing_records {
        existing_by_name
            .entry(&record.name)
            .or_default()
            .push(record);
    }
    let mut desired_by_name: HashMap<&OwnerName, Vec<&DesiredRecord>> =
        HashMap::with_capacity(desired.len());
    for record in desired {
        desired_by_name
            .entry(&record.stored_name)
            .or_default()
            .push(record);
    }

    let desired_matches_existing = |existing: &Record| {
        desired_by_name
            .get(&existing.name)
            .is_some_and(|ds| ds.iter().any(|d| d.matches(existing)))
    };
    // Upsert only touches the names and types the file speaks about.
    let desired_key_matches_existing = |existing: &Record| {
        desired_by_name.get(&existing.name).is_some_and(|ds| {
            ds.iter()
                .any(|d| d.prepared.record_type == existing.record_type)
        })
    };
    let dels: Vec<Record> = match mode {
        ImportMode::Append => Vec::new(),
        ImportMode::Replace => existing_records
            .iter()
            .filter(|e| !is_protected(zone, e) && !desired_matches_existing(e))
            .cloned()
            .collect(),
        ImportMode::Upsert => existing_records
            .iter()
            .filter(|e| {
                desired_key_matches_existing(e)
                    && !is_protected(zone, e)
                    && !desired_matches_existing(e)
            })
            .cloned()
            .collect(),
    };

    // Append leaves what it finds, so a TTL it disagrees with stays.
    let reconcile_ttl = matches!(mode, ImportMode::Upsert | ImportMode::Replace);

    let mut ttl_dels = Vec::new();
    let mut adds = Vec::new();
    let mut unchanged = 0;
    let mut updated = 0;
    for d in desired {
        let desired_ttl = d.prepared.ttl.unwrap_or(zone.default_ttl);
        let mut present = false;
        let mut stale = false;
        if let Some(es) = existing_by_name.get(&d.stored_name) {
            for e in es {
                if d.matches(e) {
                    present = true;
                    // Journal the old and new TTL as DEL+ADD so IXFR can replay it.
                    if reconcile_ttl && e.ttl != desired_ttl {
                        ttl_dels.push((*e).clone());
                        stale = true;
                    }
                }
            }
        }

        if !present {
            adds.push(d);
        } else if stale {
            updated += 1;
            adds.push(d);
        } else {
            unchanged += 1;
        }
    }

    ImportPlan {
        dels,
        ttl_dels,
        adds,
        unchanged,
        updated,
    }
}

impl ImportPlan<'_> {
    /// Preview against the same zone and record snapshot used to compute this plan.
    pub(crate) fn diff(&self, zone: &Zone, existing: &[Record]) -> RecordDiff {
        let deleted_ids: HashSet<i32> = self
            .dels
            .iter()
            .chain(&self.ttl_dels)
            .map(|r| r.id)
            .collect();

        let before: Vec<ReconstructedRecord> = existing
            .iter()
            .cloned()
            .map(ReconstructedRecord::from)
            .collect();
        let mut after: Vec<ReconstructedRecord> = existing
            .iter()
            .filter(|record| !deleted_ids.contains(&record.id))
            .cloned()
            .map(ReconstructedRecord::from)
            .collect();
        after.extend(self.adds.iter().map(|add| ReconstructedRecord {
            name: add.stored_name.clone(),
            record_type: add.prepared.record_type.clone(),
            value: add.prepared.value.clone(),
            ttl: add.prepared.ttl.unwrap_or(zone.default_ttl),
            priority: add.prepared.priority,
        }));

        build_record_diff(zone, &before, &after)
    }
}

#[cfg(test)]
mod tests;
