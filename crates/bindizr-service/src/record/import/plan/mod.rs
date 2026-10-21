//! Reconcile imported records and build their preview without writing rows.

use std::collections::{HashMap, HashSet};

use bindizr_core::{
    dns::name::OwnerName,
    model::record::{RecordId, RecordKey},
};

use crate::{
    authorization::Caller,
    model::{
        record::{Record, RecordData, RecordType},
        zone::Zone,
    },
    types::{ImportMode, RecordDiffResponse},
    zone::diff::build_record_diff,
};

/// A record the import wants present, with its owner name already normalized so
/// it can be compared against existing records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DesiredRecord {
    pub(crate) data: RecordData,
    pub(crate) source_name: String,
}

/// What an import will change, decided before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportPlan<'a> {
    pub(crate) dels: Vec<Record>,
    /// Reinserted through `adds`; kept apart so the summary counts them as updates.
    pub(crate) ttl_dels: Vec<Record>,
    pub(crate) adds: Vec<&'a DesiredRecord>,
    pub(crate) unchanged: usize,
    pub(crate) updated: usize,
}

impl<'a> ImportPlan<'a> {
    /// Reconcile the file against the zone under `mode`, matching records by
    /// identity; TTL is reconciled separately.
    pub(crate) fn compute(
        mode: ImportMode,
        existing_records: &[Record],
        desired: &'a [DesiredRecord],
    ) -> Self {
        let existing_keys: Vec<RecordKey> =
            existing_records.iter().map(Record::match_key).collect();
        let mut existing_by_key: HashMap<&RecordKey, Vec<&Record>> =
            HashMap::with_capacity(existing_records.len());

        for (record, key) in existing_records.iter().zip(&existing_keys) {
            existing_by_key.entry(key).or_default().push(record);
        }

        let desired_keys: Vec<RecordKey> = desired
            .iter()
            .map(|desired_record| desired_record.data.match_key())
            .collect();
        let desired_key_set: HashSet<&RecordKey> = desired_keys.iter().collect();

        // Upsert only touches the names and types the file speaks about.
        let desired_set_keys: HashSet<(&OwnerName, RecordType)> = desired
            .iter()
            .map(|desired_record| (&desired_record.data.name, desired_record.data.record_type))
            .collect();

        let dels: Vec<Record> = match mode {
            ImportMode::Append => Vec::new(),
            ImportMode::Replace => existing_records
                .iter()
                .zip(&existing_keys)
                .filter(|(_, key)| !desired_key_set.contains(key))
                .map(|(existing_record, _)| existing_record.clone())
                .collect(),
            ImportMode::Upsert => existing_records
                .iter()
                .zip(&existing_keys)
                .filter(|(existing_record, key)| {
                    desired_set_keys.contains(&(&existing_record.name, existing_record.record_type))
                        && !desired_key_set.contains(key)
                })
                .map(|(existing_record, _)| existing_record.clone())
                .collect(),
        };

        // Append leaves what it finds, so a TTL it disagrees with stays.
        let reconcile_ttl = matches!(mode, ImportMode::Upsert | ImportMode::Replace);

        let mut ttl_dels = Vec::new();
        let mut adds = Vec::new();
        let mut unchanged = 0;
        let mut updated = 0;

        for (desired_record, key) in desired.iter().zip(&desired_keys) {
            let desired_ttl = desired_record.data.ttl;
            let mut present = false;
            let mut stale = false;

            for existing_record in existing_by_key.get(key).into_iter().flatten() {
                present = true;
                // Journal the old and new TTL as DEL+ADD so IXFR can replay it.
                if reconcile_ttl && existing_record.ttl != desired_ttl {
                    ttl_dels.push((*existing_record).clone());
                    stale = true;
                }
            }

            if !present {
                adds.push(desired_record);
            } else if stale {
                updated += 1;
                adds.push(desired_record);
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
}

impl ImportPlan<'_> {
    /// Preview against the same zone and record snapshot used to compute
    /// this plan, showing the existing rows `caller` may read.
    pub(crate) fn diff(
        &self,
        caller: &Caller,
        zone: &Zone,
        existing: &[Record],
    ) -> RecordDiffResponse {
        let deleted_ids: HashSet<RecordId> = self
            .dels
            .iter()
            .chain(&self.ttl_dels)
            .map(|record| record.id)
            .collect();

        let before =
            caller.readable_records(zone.id, existing.iter().cloned().map(RecordData::from));
        let mut after = caller.readable_records(
            zone.id,
            existing
                .iter()
                .filter(|record| !deleted_ids.contains(&record.id))
                .cloned()
                .map(RecordData::from),
        );

        for add in &self.adds {
            after.push_written(add.data.clone());
        }

        build_record_diff(zone, &before, &after)
    }
}

#[cfg(test)]
mod tests;
