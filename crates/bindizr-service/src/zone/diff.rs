//! RRset-level diffing of two serials' records: what an import, a bulk apply, or a
//! rollback would add, remove, or change.

use std::collections::BTreeMap;

use crate::{
    model::{
        record::{RecordData, RecordSetKey},
        zone::Zone,
    },
    types::{
        RecordChange, RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue,
        build_display_value,
    },
};

/// What makes two records of one record set the same: canonical rdata and TTL.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MemberIdentity {
    rdata: String,
    ttl: i32,
}

/// One record within an RRset: its identity (for change detection) and
/// its display-form value (for the response).
#[derive(Clone)]
struct RecordSetMember {
    identity: MemberIdentity,
    value: RecordDiffValue,
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
            record_type: record.record_type.to_string(),
        };
        record_sets.entry(key).or_default().push(RecordSetMember {
            identity: MemberIdentity {
                rdata: record
                    .record_type
                    .canonical_value(&record.value, record.priority)
                    .into_owned(),
                ttl: record.ttl,
            },
            value: RecordDiffValue {
                value: build_display_value(&record.value, &record.record_type),
                ttl: record.ttl,
                priority: record.priority,
            },
        });
    }
    record_sets
}

/// Collect sorted, borrowed record identities for comparison without copying their contents.
fn record_set_identities(record_set: &[RecordSetMember]) -> Vec<&MemberIdentity> {
    let mut ids: Vec<_> = record_set.iter().map(|r| &r.identity).collect();
    ids.sort();
    ids
}

/// Collect the record values belonging to an owner and type.
fn record_set_values(record_set: Vec<RecordSetMember>) -> Vec<RecordDiffValue> {
    record_set.into_iter().map(|r| r.value).collect()
}

/// Diff two serials' records at the RRset level. TTL is part of a record's identity,
/// so a TTL-only change shows as `changed`.
pub(crate) fn build_record_diff(
    zone: &Zone,
    before: &[RecordData],
    after: &[RecordData],
) -> RecordDiff {
    let mut before_record_sets = group_record_sets(zone, before);
    let mut after_record_sets = group_record_sets(zone, after);

    let mut keys: Vec<RecordSetKey> = before_record_sets.keys().cloned().collect();
    keys.extend(
        after_record_sets
            .keys()
            .filter(|k| !before_record_sets.contains_key(*k))
            .cloned(),
    );
    keys.sort();

    let mut entries = Vec::new();
    let (mut added, mut removed, mut changed) = (0u64, 0u64, 0u64);

    for key in keys {
        // Both maps are drained here, so each RRset can be moved into its entry.
        let before = before_record_sets.remove(&key);
        let after = after_record_sets.remove(&key);
        let RecordSetKey { name, record_type } = key;
        match (before, after) {
            (None, Some(after)) => {
                added += 1;
                entries.push(RecordDiffEntry {
                    change: RecordChange::Added,
                    name,
                    record_type,
                    from: Vec::new(),
                    to: record_set_values(after),
                });
            }
            (Some(before), None) => {
                removed += 1;
                entries.push(RecordDiffEntry {
                    change: RecordChange::Removed,
                    name,
                    record_type,
                    from: record_set_values(before),
                    to: Vec::new(),
                });
            }
            (Some(before), Some(after)) => {
                if record_set_identities(&before) != record_set_identities(&after) {
                    changed += 1;
                    entries.push(RecordDiffEntry {
                        change: RecordChange::Changed,
                        name,
                        record_type,
                        from: record_set_values(before),
                        to: record_set_values(after),
                    });
                }
            }
            (None, None) => unreachable!("keys come from one of the two maps"),
        }
    }

    RecordDiff {
        entries,
        summary: RecordDiffSummary {
            added,
            removed,
            changed,
        },
    }
}
