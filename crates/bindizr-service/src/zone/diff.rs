//! Record-set-level diffing of two serials' records: what an import, a bulk apply, or a
//! rollback would add, remove, or change.

use std::collections::{BTreeMap, HashSet};

use bindizr_core::dns::Ttl;
use bindizr_core::model::record::{Record, RecordData, RecordSetKey, RecordValueKey};
use bindizr_core::model::zone::Zone;

use crate::authorization::ReadableRecords;
use crate::types;
use crate::types::{
    RecordChange, RecordDiffEntryResponse, RecordDiffResponse, RecordDiffSummaryResponse,
    RecordDiffValueResponse,
};

/// What makes two records of one record set the same: value identity and TTL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MemberIdentity {
    value_key: RecordValueKey<'static>,
    ttl: Ttl,
}

/// One record within a record set: its identity (for change detection) and
/// its display-form value (for the response).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordSetMember {
    identity: MemberIdentity,
    value: RecordDiffValueResponse,
}

/// Preview deletions and the caller's own writes against authorized existing records.
pub(crate) fn build_record_preview(
    zone: &Zone,
    mut existing: ReadableRecords<Record>,
    deleted: &[Record],
    written: impl IntoIterator<Item = RecordData>,
) -> RecordDiffResponse {
    let before = existing.clone().into_data();
    let deleted_record_ids: HashSet<_> = deleted.iter().map(|record| record.id).collect();
    existing.remove_ids(&deleted_record_ids);
    let mut after = existing.into_data();

    for record in written {
        after.push_written(record);
    }

    build_record_diff(zone, &before, &after)
}

/// Group records into record sets. Two records are the same iff their canonical
/// value+priority and TTL match.
fn group_record_sets(
    zone: &Zone,
    records: &[RecordData],
) -> BTreeMap<RecordSetKey, Vec<RecordSetMember>> {
    let mut record_sets: BTreeMap<RecordSetKey, Vec<RecordSetMember>> = BTreeMap::new();

    for record in records {
        let key = RecordSetKey {
            name: record.name.to_fqdn(&zone.name),
            record_type: record.record_type,
        };
        record_sets.entry(key).or_default().push(RecordSetMember {
            identity: MemberIdentity {
                value_key: record
                    .record_type
                    .to_comparison_key(&record.value, record.priority)
                    .into_owned(),
                ttl: record.ttl,
            },
            value: RecordDiffValueResponse {
                value: types::build_display_value(record.record_type, &record.value),
                ttl: record.ttl,
                priority: record.priority,
            },
        });
    }

    record_sets
}

/// Collect sorted, borrowed record identities for comparison without copying their contents.
fn record_set_identities(record_set: &[RecordSetMember]) -> Vec<&MemberIdentity> {
    let mut identities: Vec<_> = record_set.iter().map(|record| &record.identity).collect();
    identities.sort();
    identities
}

/// Collect the record values belonging to an owner and type.
fn record_set_values(record_set: Vec<RecordSetMember>) -> Vec<RecordDiffValueResponse> {
    record_set.into_iter().map(|record| record.value).collect()
}

/// Diff authorized [`ReadableRecords`] by record set, counting TTL-only edits as changes.
pub(crate) fn build_record_diff(
    zone: &Zone,
    before: &ReadableRecords<RecordData>,
    after: &ReadableRecords<RecordData>,
) -> RecordDiffResponse {
    let before_record_sets = group_record_sets(zone, before.as_slice());
    let mut after_record_sets = group_record_sets(zone, after.as_slice());

    // Each record set before is removed or changed; what is left after is added.
    let mut changes = Vec::new();

    for (key, before) in before_record_sets {
        match after_record_sets.remove(&key) {
            Some(after) => {
                if record_set_identities(&before) != record_set_identities(&after) {
                    changes.push((key, RecordChange::Changed, before, after));
                }
            }
            None => changes.push((key, RecordChange::Removed, before, Vec::new())),
        }
    }

    changes.extend(
        after_record_sets
            .into_iter()
            .map(|(key, after)| (key, RecordChange::Added, Vec::new(), after)),
    );
    changes.sort_by(|left, right| left.0.cmp(&right.0));

    let mut entries = Vec::with_capacity(changes.len());
    let (mut added, mut removed, mut changed) = (0u64, 0u64, 0u64);

    for (RecordSetKey { name, record_type }, change, before, after) in changes {
        match change {
            RecordChange::Added => added += 1,
            RecordChange::Removed => removed += 1,
            RecordChange::Changed => changed += 1,
        }

        entries.push(RecordDiffEntryResponse {
            change,
            name,
            record_type,
            from: record_set_values(before),
            to: record_set_values(after),
        });
    }

    RecordDiffResponse {
        entries,
        summary: RecordDiffSummaryResponse {
            added,
            removed,
            changed,
        },
    }
}
