//! RRset-level diffing of two serials' records: what an import, a bulk apply, or a
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

/// One record within an RRset: its identity (for change detection) and
/// its display-form value (for the response).
#[derive(Clone)]
struct RrsetRecord {
    identity: (String, i32),
    value: RecordDiffValue,
}

/// Group records into RRsets keyed by (display owner name, record type). Two
/// records are the same iff their canonical value+priority and TTL match.
fn group_rrsets(
    zone: &Zone,
    records: &[ReconstructedRecord],
) -> BTreeMap<(String, String), Vec<RrsetRecord>> {
    let mut rrsets: BTreeMap<(String, String), Vec<RrsetRecord>> = BTreeMap::new();
    for record in records {
        let key = (
            record.name.to_fqdn(&zone.name),
            record.record_type.to_string(),
        );
        rrsets.entry(key).or_default().push(RrsetRecord {
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
    rrsets
}

/// Borrowed so the two sides can be compared without copying every identity.
fn rrset_identities(rrset: &[RrsetRecord]) -> Vec<&(String, i32)> {
    let mut ids: Vec<_> = rrset.iter().map(|r| &r.identity).collect();
    ids.sort();
    ids
}

fn rrset_values(rrset: Vec<RrsetRecord>) -> Vec<RecordDiffValue> {
    rrset.into_iter().map(|r| r.value).collect()
}

/// Diff two serials' records at the RRset level. TTL is part of a record's identity,
/// so a TTL-only change shows as `changed`.
pub(crate) fn build_record_diff(
    zone: &Zone,
    before: &[ReconstructedRecord],
    after: &[ReconstructedRecord],
) -> RecordDiff {
    let mut before_rrsets = group_rrsets(zone, before);
    let mut after_rrsets = group_rrsets(zone, after);

    let mut keys: Vec<(String, String)> = before_rrsets.keys().cloned().collect();
    keys.extend(
        after_rrsets
            .keys()
            .filter(|k| !before_rrsets.contains_key(*k))
            .cloned(),
    );
    keys.sort();

    let mut entries = Vec::new();
    let (mut added, mut removed, mut changed) = (0usize, 0usize, 0usize);

    for key in keys {
        // Both maps are drained here, so each RRset can be moved into its entry.
        let before = before_rrsets.remove(&key);
        let after = after_rrsets.remove(&key);
        let (name, record_type) = key;
        match (before, after) {
            (None, Some(after)) => {
                added += 1;
                entries.push(RecordDiffEntry {
                    change: "added".to_string(),
                    name,
                    record_type,
                    from: Vec::new(),
                    to: rrset_values(after),
                });
            }
            (Some(before), None) => {
                removed += 1;
                entries.push(RecordDiffEntry {
                    change: "removed".to_string(),
                    name,
                    record_type,
                    from: rrset_values(before),
                    to: Vec::new(),
                });
            }
            (Some(before), Some(after)) => {
                if rrset_identities(&before) != rrset_identities(&after) {
                    changed += 1;
                    entries.push(RecordDiffEntry {
                        change: "changed".to_string(),
                        name,
                        record_type,
                        from: rrset_values(before),
                        to: rrset_values(after),
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
