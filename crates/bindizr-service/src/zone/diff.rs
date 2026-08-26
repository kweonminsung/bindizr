//! RRset-level diffing of two record sets: what an import, a bulk apply, or a
//! rollback would add, remove, or change.

use std::collections::BTreeMap;

use crate::{
    model::zone::Zone,
    types::{
        RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue,
        display_record_value_request,
    },
    zone::history::ReconstructedRecord,
};

/// One record within an RRset group: its identity (for change detection) and
/// its display-form value (for the response).
#[derive(Clone)]
struct GroupedRecord {
    identity: (String, i32),
    value: RecordDiffValue,
}

/// Group records into RRsets keyed by (display owner name, record type). Two
/// records are the same iff their canonical value+priority and TTL match.
fn group_rrsets(
    zone: &Zone,
    records: &[ReconstructedRecord],
) -> BTreeMap<(String, String), Vec<GroupedRecord>> {
    let mut groups: BTreeMap<(String, String), Vec<GroupedRecord>> = BTreeMap::new();
    for record in records {
        let key = (
            record.name.to_fqdn(&zone.name),
            record.record_type.to_string(),
        );
        groups.entry(key).or_default().push(GroupedRecord {
            identity: (
                record
                    .record_type
                    .canonical_value(&record.value, record.priority)
                    .into_owned(),
                record.ttl,
            ),
            value: RecordDiffValue {
                value: display_record_value_request(&record.value, &record.record_type),
                ttl: record.ttl,
                priority: record.priority,
            },
        });
    }
    groups
}

/// Borrowed so the two sides can be compared without copying every identity.
fn group_identities(group: &[GroupedRecord]) -> Vec<&(String, i32)> {
    let mut ids: Vec<_> = group.iter().map(|r| &r.identity).collect();
    ids.sort();
    ids
}

fn group_values(group: Vec<GroupedRecord>) -> Vec<RecordDiffValue> {
    group.into_iter().map(|r| r.value).collect()
}

/// Diff two record sets at the RRset level. TTL is part of a record's identity,
/// so a TTL-only change shows as `changed`.
pub(crate) fn build_record_diff(
    zone: &Zone,
    before: &[ReconstructedRecord],
    after: &[ReconstructedRecord],
) -> RecordDiff {
    let mut before_groups = group_rrsets(zone, before);
    let mut after_groups = group_rrsets(zone, after);

    let mut keys: Vec<(String, String)> = before_groups.keys().cloned().collect();
    keys.extend(
        after_groups
            .keys()
            .filter(|k| !before_groups.contains_key(*k))
            .cloned(),
    );
    keys.sort();

    let mut entries = Vec::new();
    let (mut added, mut removed, mut changed) = (0usize, 0usize, 0usize);

    for key in keys {
        // Both maps are drained here, so each group can be moved into its entry.
        let before = before_groups.remove(&key);
        let after = after_groups.remove(&key);
        let (name, record_type) = key;
        match (before, after) {
            (None, Some(after)) => {
                added += 1;
                entries.push(RecordDiffEntry {
                    change: "added".to_string(),
                    name,
                    record_type,
                    from: Vec::new(),
                    to: group_values(after),
                });
            }
            (Some(before), None) => {
                removed += 1;
                entries.push(RecordDiffEntry {
                    change: "removed".to_string(),
                    name,
                    record_type,
                    from: group_values(before),
                    to: Vec::new(),
                });
            }
            (Some(before), Some(after)) => {
                if group_identities(&before) != group_identities(&after) {
                    changed += 1;
                    entries.push(RecordDiffEntry {
                        change: "changed".to_string(),
                        name,
                        record_type,
                        from: group_values(before),
                        to: group_values(after),
                    });
                }
            }
            (None, None) => unreachable!("keys come from the two group maps"),
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
