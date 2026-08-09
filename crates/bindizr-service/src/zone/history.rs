//! Zone serial history: snapshot listing, point-in-time record reconstruction,
//! and serial-based rollback.

use std::collections::{BTreeMap, HashMap, HashSet};

use bindizr_core::dns::{
    name::{OwnerName, ZoneName},
    record::SoaMailbox,
};
use chrono::Utc;

use super::{
    ZoneService, apex_ns_rrset_ttl, update::soa_replacement_changes,
    validation::normalize_zone_name,
};
use crate::{
    RepositoryTx,
    authorization::Caller,
    error::ServiceError,
    log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
        zone_change::ZoneChange,
        zone_snapshot::ZoneSnapshot,
    },
    record::{
        RecordService, validate_delete_constraints, validate_record_add_constraints_normalized,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{
        PaginatedResponse, RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue,
        RollbackSummary, RollbackZoneResponse, SnapshotDiffResponse, display_record_value_request,
    },
};

/// A record as it existed at a past serial, rebuilt from the change history;
/// carries no database id.
#[derive(Debug, Clone)]
pub struct ReconstructedRecord {
    pub name: String,
    pub record_type: RecordType,
    pub value: String,
    pub ttl: i32,
    pub priority: Option<i32>,
}

impl From<Record> for ReconstructedRecord {
    fn from(record: Record) -> Self {
        ReconstructedRecord {
            name: record.name,
            record_type: record.record_type,
            value: record.value,
            ttl: record.ttl,
            priority: record.priority,
        }
    }
}

/// Hash key identifying a record for set matching: lowercased owner name,
/// type, and the canonical comparison form of the value(+priority).
type MatchKey = (String, String, String);

fn match_key(name: &str, record_type: &RecordType, value: &str, priority: Option<i32>) -> MatchKey {
    (
        name.to_ascii_lowercase(),
        record_type.to_string(),
        record_type.canonical_value(value, priority).into_owned(),
    )
}

fn record_match_key(record: &Record) -> MatchKey {
    match_key(
        &record.name,
        &record.record_type,
        &record.value,
        record.priority,
    )
}

/// Reverse-apply the zone's change history in `(target_serial, current_serial]`
/// onto the current record set, yielding the record set at `target_serial`.
/// SOA rows are skipped (SOA state is restored from `zone_soa_history`).
async fn reconstruct_records_at_serial(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    target_serial: i32,
    current_serial: i32,
) -> Result<Vec<ReconstructedRecord>, ServiceError> {
    let mut state: HashMap<MatchKey, Vec<ReconstructedRecord>> = HashMap::new();
    for record in RepositoryService::get_records_by_zone_id_tx(tx, zone_id).await? {
        state
            .entry(record_match_key(&record))
            .or_default()
            .push(record.into());
    }

    let changes = RepositoryService::get_zone_changes_between_serials_tx(
        tx,
        zone_id,
        target_serial,
        current_serial,
    )
    .await?;

    // Changes arrive ordered by (serial, id) ascending; undo them newest-first.
    for change in changes.iter().rev() {
        if change.record_type == "SOA" {
            continue;
        }
        let record_type: RecordType = match change.record_type.parse() {
            Ok(record_type) => record_type,
            Err(_) => {
                log_warn!(
                    "Skipping zone change with unknown record type '{}' during reconstruction",
                    change.record_type
                );
                continue;
            }
        };
        let key = match_key(
            &change.record_name,
            &record_type,
            &change.record_value,
            change.record_priority,
        );

        match change.operation.as_str() {
            ZoneChange::OP_ADD => match state.get_mut(&key).and_then(Vec::pop) {
                Some(_) => {}
                // Tolerated: history anomalies (e.g. rows removed outside
                // the change log) must not brick reconstruction.
                None => log_warn!(
                    "No matching record to undo ADD of '{}' {} during reconstruction",
                    change.record_name,
                    change.record_type
                ),
            },
            ZoneChange::OP_DEL => {
                // The recorded row existed before this serial; restore it.
                state.entry(key).or_default().push(ReconstructedRecord {
                    name: change.record_name.clone(),
                    record_type,
                    value: change.record_value.clone(),
                    ttl: change.record_ttl,
                    priority: change.record_priority,
                });
            }
            other => log_warn!(
                "Skipping zone change with unknown operation '{}' during reconstruction",
                other
            ),
        }
    }

    let mut records: Vec<ReconstructedRecord> = state.into_values().flatten().collect();
    sort_records(&mut records);
    Ok(records)
}

/// The record set at `serial`: the live records when it is the current serial,
/// otherwise reconstructed from the change history.
async fn records_at_serial(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    serial: i32,
    current_serial: i32,
) -> Result<Vec<ReconstructedRecord>, ServiceError> {
    if serial == current_serial {
        let mut records: Vec<ReconstructedRecord> =
            RepositoryService::get_records_by_zone_id_tx(tx, zone_id)
                .await?
                .into_iter()
                .map(ReconstructedRecord::from)
                .collect();
        sort_records(&mut records);
        Ok(records)
    } else {
        reconstruct_records_at_serial(tx, zone_id, serial, current_serial).await
    }
}

/// A serial is diffable only if it is the current serial or has a snapshot.
async fn require_serial(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    serial: i32,
) -> Result<(), ServiceError> {
    if serial == zone.serial {
        return Ok(());
    }
    RepositoryService::get_zone_snapshot_by_serial_tx(tx, zone.id, serial)
        .await?
        .ok_or_else(|| ServiceError::snapshot_not_found(&zone.name, serial))?;
    Ok(())
}

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
            OwnerName::from_row(&record.name).to_fqdn(&ZoneName::from_row(&zone.name)),
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

fn group_identities(group: &[GroupedRecord]) -> Vec<(String, i32)> {
    let mut ids: Vec<_> = group.iter().map(|r| r.identity.clone()).collect();
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
    let before_groups = group_rrsets(zone, before);
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
        let (name, record_type) = key.clone();
        let before = before_groups.get(&key);
        let after = after_groups.remove(&key);
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
                    from: group_values(before.clone()),
                    to: Vec::new(),
                });
            }
            (Some(before), Some(after)) => {
                if group_identities(before) != group_identities(&after) {
                    changed += 1;
                    entries.push(RecordDiffEntry {
                        change: "changed".to_string(),
                        name,
                        record_type,
                        from: group_values(before.clone()),
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

/// Deterministic output order (hash-map iteration order is not).
fn sort_records(records: &mut [ReconstructedRecord]) {
    records.sort_by(|a, b| {
        (&a.name, a.record_type.to_string(), &a.value).cmp(&(
            &b.name,
            b.record_type.to_string(),
            &b.value,
        ))
    });
}

/// Build the zone as it should look after rolling back to `snapshot`: SOA
/// metadata from the snapshot, identity (id/name) and creation time unchanged,
/// serial advanced to `new_serial`.
fn restored_zone_from_snapshot(
    zone: &Zone,
    snapshot: &ZoneSnapshot,
    new_serial: i32,
) -> Result<Zone, ServiceError> {
    let admin_email = SoaMailbox::from_encoded(&snapshot.admin_email)
        .to_email()
        .map_err(|e| {
            ServiceError::internal(format!("Failed to decode snapshot admin email: {}", e))
        })?;

    Ok(Zone {
        id: zone.id,
        name: zone.name.clone(),
        primary_ns: snapshot.primary_ns.clone(),
        admin_email,
        ttl: snapshot.ttl,
        serial: new_serial,
        refresh: snapshot.refresh,
        retry: snapshot.retry,
        expire: snapshot.expire,
        minimum_ttl: snapshot.minimum_ttl,
        created_at: zone.created_at,
    })
}

fn soa_metadata_changed(zone: &Zone, restored: &Zone) -> bool {
    zone.primary_ns != restored.primary_ns
        || zone.admin_email != restored.admin_email
        || zone.ttl != restored.ttl
        || zone.refresh != restored.refresh
        || zone.retry != restored.retry
        || zone.expire != restored.expire
        || zone.minimum_ttl != restored.minimum_ttl
}

impl ZoneService {
    /// List a zone's snapshots (serial history), newest serial first.
    pub async fn list_snapshots(
        zone_name: &str,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<PaginatedResponse<ZoneSnapshot>, ServiceError> {
        Self::list_snapshots_for(&Caller::Global, zone_name, limit, offset).await
    }

    /// Like [`Self::list_snapshots`], checking visibility on the row whose id
    /// the queries use, so a same-name recreation cannot swap the zone in.
    pub async fn list_snapshots_for(
        caller: &Caller,
        zone_name: &str,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<PaginatedResponse<ZoneSnapshot>, ServiceError> {
        let zone = Self::get_by_name(zone_name).await?;
        // Invisible zones read as 404 so scoped tokens cannot probe them.
        if !caller.zone_visible(zone.id) {
            return Err(ServiceError::zone_not_found(zone_name));
        }

        let total = RepositoryService::count_zone_snapshots(zone.id).await?;
        let effective_limit = limit.unwrap_or(50);
        let items =
            RepositoryService::list_zone_snapshots(zone.id, effective_limit, offset.unwrap_or(0))
                .await?;

        Ok(crate::pagination::paginated_response(
            items,
            Some(effective_limit),
            offset,
            total,
        ))
    }

    /// Fetch the snapshot at `serial` together with the reconstructed record
    /// set at that serial.
    pub async fn get_snapshot(
        zone_name: &str,
        serial: i32,
    ) -> Result<(ZoneSnapshot, Vec<ReconstructedRecord>), ServiceError> {
        Self::get_snapshot_for(&Caller::Global, zone_name, serial).await
    }

    /// Like [`Self::get_snapshot`], checking visibility on the row this tx
    /// locked so a same-name recreation cannot swap the zone in.
    pub async fn get_snapshot_for(
        caller: &Caller,
        zone_name: &str,
        serial: i32,
    ) -> Result<(ZoneSnapshot, Vec<ReconstructedRecord>), ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to load snapshot").await?;

        let result = async {
            let zone = ZoneService::get_by_name_tx(&mut tx, &lookup_name).await?;
            if !caller.zone_visible(zone.id) {
                return Err(ServiceError::zone_not_found(zone_name));
            }
            let snapshot =
                RepositoryService::get_zone_snapshot_by_serial_tx(&mut tx, zone.id, serial)
                    .await?
                    .ok_or_else(|| ServiceError::snapshot_not_found(&zone.name, serial))?;

            let records = records_at_serial(&mut tx, zone.id, serial, zone.serial).await?;

            Ok::<_, ServiceError>((snapshot, records))
        }
        .await;

        RepositoryService::finish_tx(tx, result, "Failed to load snapshot").await
    }

    /// Compute the record-level difference between two of a zone's serials.
    /// `to_serial` defaults to the zone's current serial when `None`. Each
    /// serial must be the current one or an existing snapshot.
    pub async fn diff_snapshots(
        zone_name: &str,
        from_serial: i32,
        to_serial: Option<i32>,
    ) -> Result<SnapshotDiffResponse, ServiceError> {
        Self::diff_snapshots_for(&Caller::Global, zone_name, from_serial, to_serial).await
    }

    /// Like [`Self::diff_snapshots`], checking visibility on the row this tx
    /// locked so a same-name recreation cannot swap the zone in.
    pub async fn diff_snapshots_for(
        caller: &Caller,
        zone_name: &str,
        from_serial: i32,
        to_serial: Option<i32>,
    ) -> Result<SnapshotDiffResponse, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to diff snapshots").await?;

        let result = async {
            let zone = ZoneService::get_by_name_tx(&mut tx, &lookup_name).await?;
            if !caller.zone_visible(zone.id) {
                return Err(ServiceError::zone_not_found(zone_name));
            }
            let to_serial = to_serial.unwrap_or(zone.serial);

            require_serial(&mut tx, &zone, from_serial).await?;
            require_serial(&mut tx, &zone, to_serial).await?;

            let from_records =
                records_at_serial(&mut tx, zone.id, from_serial, zone.serial).await?;
            let to_records = records_at_serial(&mut tx, zone.id, to_serial, zone.serial).await?;

            Ok::<_, ServiceError>(SnapshotDiffResponse {
                from_serial,
                to_serial,
                diff: build_record_diff(&zone, &from_records, &to_records),
            })
        }
        .await;

        RepositoryService::finish_tx(tx, result, "Failed to diff snapshots").await
    }

    /// Roll a zone back to the state captured at `target_serial`. The record
    /// set and SOA metadata return to that serial's state while the zone's
    /// serial advances to a new value (serials never go backward). The zone
    /// name is not part of a snapshot and is never restored.
    pub async fn rollback(
        zone_name: &str,
        target_serial: i32,
        dry_run: bool,
    ) -> Result<RollbackZoneResponse, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to roll back zone").await?;

        let apply_result = async {
            let zone = ZoneService::get_by_name_tx(&mut tx, &lookup_name).await?;

            if target_serial < 1 || target_serial >= zone.serial {
                return Err(ServiceError::invalid_input(format!(
                    "target serial {} must be less than the current serial {}",
                    target_serial, zone.serial
                )));
            }
            let snapshot =
                RepositoryService::get_zone_snapshot_by_serial_tx(&mut tx, zone.id, target_serial)
                    .await?
                    .ok_or_else(|| ServiceError::snapshot_not_found(&zone.name, target_serial))?;

            let new_serial = generate_serial(Some(zone.serial))?;
            let restored_zone = restored_zone_from_snapshot(&zone, &snapshot, new_serial)?;
            let soa_changed = soa_metadata_changed(&zone, &restored_zone);

            let current_records =
                RepositoryService::get_records_by_zone_id_tx(&mut tx, zone.id).await?;
            let target_records =
                reconstruct_records_at_serial(&mut tx, zone.id, target_serial, zone.serial).await?;

            // Diff current vs target, import-Replace style. Protection is
            // evaluated against the restored zone so the restored primary_ns's
            // apex NS is kept and the newer one becomes deletable.
            let mut target_by_key: HashMap<MatchKey, Vec<ReconstructedRecord>> = HashMap::new();
            for target in target_records {
                let key = match_key(
                    &target.name,
                    &target.record_type,
                    &target.value,
                    target.priority,
                );
                target_by_key.entry(key).or_default().push(target);
            }

            let mut dels: Vec<Record> = Vec::new();
            let mut unchanged = 0usize;
            let mut to_add: Vec<ReconstructedRecord> = Vec::new();

            for record in &current_records {
                let key = record_match_key(record);
                match target_by_key.get_mut(&key).and_then(Vec::pop) {
                    Some(target) => {
                        // TTL-only difference: replace the row (DEL + ADD).
                        // The pair preserves the record's identity, so the
                        // primary_ns delete protection cannot be violated; SOA
                        // lives in the zone's own fields.
                        if record.ttl != target.ttl && record.record_type != RecordType::SOA {
                            dels.push(record.clone());
                            to_add.push(target);
                        } else {
                            unchanged += 1;
                        }
                    }
                    None => {
                        if validate_delete_constraints(&restored_zone, std::slice::from_ref(record))
                            .is_ok()
                        {
                            dels.push(record.clone());
                        } else {
                            // Protected rows (SOA / restored primary NS) stay.
                            unchanged += 1;
                        }
                    }
                }
            }
            to_add.extend(target_by_key.into_values().flatten());

            // The restored primary_ns must keep a matching apex NS record.
            let deleted_ids: HashSet<i32> = dels.iter().map(|del| del.id).collect();
            let surviving = |record: &&Record| !deleted_ids.contains(&record.id);
            let has_primary_ns = current_records
                .iter()
                .filter(surviving)
                .any(|r| restored_zone.is_primary_ns(&r.record_type, &r.name, &r.value))
                || to_add
                    .iter()
                    .any(|r| restored_zone.is_primary_ns(&r.record_type, &r.name, &r.value));
            if !has_primary_ns {
                // Prefer a restored TTL: the restore is what this serial expresses.
                let candidates = to_add
                    .iter()
                    .map(|r| (&r.record_type, r.name.as_str(), r.ttl))
                    .chain(
                        current_records
                            .iter()
                            .filter(surviving)
                            .map(|r| (&r.record_type, r.name.as_str(), r.ttl)),
                    );

                to_add.push(ReconstructedRecord {
                    name: OwnerName::APEX.to_string(),
                    record_type: RecordType::NS,
                    value: restored_zone.primary_ns.clone(),
                    ttl: apex_ns_rrset_ttl(&restored_zone, candidates),
                    priority: None,
                });
            }

            // Validate the adds in-memory against the post-delete record set
            // (mirrors the import reconcile).
            let mut records_by_name: HashMap<OwnerName, Vec<Record>> = HashMap::new();
            for record in &current_records {
                if deleted_ids.contains(&record.id) {
                    continue;
                }
                records_by_name
                    .entry(OwnerName::from_row(&record.name))
                    .or_default()
                    .push(record.clone());
            }
            let mut to_insert: Vec<Record> = Vec::with_capacity(to_add.len());
            for target in &to_add {
                let same_name = records_by_name
                    .entry(OwnerName::from_row(&target.name))
                    .or_default();
                validate_record_add_constraints_normalized(
                    same_name,
                    &OwnerName::from_row(&target.name),
                    &target.record_type,
                    &target.value,
                    target.ttl,
                    target.priority,
                    None,
                )?;
                let record = Record {
                    id: 0,
                    name: target.name.clone(),
                    record_type: target.record_type.clone(),
                    value: target.value.clone(),
                    ttl: target.ttl,
                    priority: target.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                };
                same_name.push(record.clone());
                to_insert.push(record);
            }

            let summary = RollbackSummary {
                records_added: to_insert.len(),
                records_deleted: dels.len(),
                records_unchanged: unchanged,
                soa_changed,
            };

            if dry_run {
                return Ok((
                    RollbackZoneResponse {
                        applied: false,
                        dry_run: true,
                        target_serial,
                        new_serial,
                        summary,
                    },
                    zone.name.clone(),
                    false,
                ));
            }

            RepositoryService::update_zone_tx(&mut tx, restored_zone.clone()).await?;

            if soa_changed {
                let changes = soa_replacement_changes(&zone, &restored_zone, new_serial)?;
                RepositoryService::create_zone_changes_tx(&mut tx, &changes).await?;
            }

            RecordService::delete_records_with_changes_tx(&mut tx, zone.id, new_serial, &dels)
                .await?;
            RecordService::insert_records_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert)
                .await?;
            ZoneService::save_snapshot_tx(&mut tx, &restored_zone, new_serial).await?;

            Ok((
                RollbackZoneResponse {
                    applied: true,
                    dry_run: false,
                    target_serial,
                    new_serial,
                    summary,
                },
                zone.name.clone(),
                true,
            ))
        }
        .await;

        let (response, zone_name, applied) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to roll back zone").await?;

        if applied {
            log_info!(
                "event=zone_rollback zone={} target_serial={} new_serial={} added={} deleted={}",
                zone_name,
                response.target_serial,
                response.new_serial,
                response.summary.records_added,
                response.summary.records_deleted
            );
            if let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
                log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
            }
        }

        Ok(response)
    }
}
