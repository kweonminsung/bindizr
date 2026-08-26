//! Zone serial history: version listing, point-in-time record reconstruction,
//! and serial-based rollback.

use std::collections::{BTreeMap, HashMap, HashSet};

use bindizr_core::dns::{name::OwnerName, record::SoaMailbox};
use bindizr_db::repository::LockLevel;
use chrono::Utc;

use super::{ZoneService, update::soa_replacement_changes, validation::normalize_zone_name};
use crate::{
    RepositoryTx,
    authorization::Caller,
    dnssec::DnssecService,
    error::ServiceError,
    log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType},
        zone_version::ZoneVersion,
    },
    record::{
        RecordService, validate_delete_constraints, validate_record_add_constraints_normalized,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{
        PaginatedResponse, RecordDiff, RecordDiffEntry, RecordDiffSummary, RecordDiffValue,
        RollbackSummary, RollbackZoneResponse, VersionDiffResponse, display_record_value_request,
    },
};

/// A record as it existed at a past serial, rebuilt from the journal;
/// carries no database id.
#[derive(Debug, Clone)]
pub struct ReconstructedRecord {
    pub(crate) name: OwnerName,
    pub(crate) record_type: RecordType,
    pub(crate) value: String,
    pub(crate) ttl: i32,
    pub(crate) priority: Option<i32>,
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

fn match_key(
    name: &OwnerName,
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> MatchKey {
    (
        name.to_stored(),
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

/// Reverse-apply the zone's journal in `(target_serial, current_serial]`
/// onto the current record set, yielding the record set at `target_serial`.
/// SOA rows are skipped (SOA state is restored from `zone_versions`).
async fn reconstruct_records_at_serial(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    target_serial: i32,
    current_serial: i32,
) -> Result<Vec<ReconstructedRecord>, ServiceError> {
    let mut state: HashMap<MatchKey, Vec<ReconstructedRecord>> = HashMap::new();
    for record in RepositoryService::list_records_tx(tx, zone_id, LockLevel::None).await? {
        state
            .entry(record_match_key(&record))
            .or_default()
            .push(record.into());
    }

    let changes = RepositoryService::list_zone_journal_between_serials_tx(
        tx,
        zone_id,
        target_serial,
        current_serial,
        LockLevel::None,
    )
    .await?;

    // Changes arrive ordered by (serial, id) ascending; undo them newest-first.
    for change in changes.iter().rev() {
        // Derived DNSSEC rows are not user data (rollback re-signs the
        // restored plane), and SOA markers are zone metadata the version row
        // already carries.
        let JournalRecordType::User(record_type) = &change.record_type else {
            continue;
        };
        let Some(record_value) = change.record_value.as_deref() else {
            log_warn!(
                "User change for '{}' {} carries no value; skipping during reconstruction",
                change.record_name,
                change.record_type
            );
            continue;
        };
        let record_type = record_type.clone();
        let key = match_key(
            &change.record_name,
            &record_type,
            record_value,
            change.record_priority,
        );

        match change.operation {
            ChangeOperation::Add => match state.get_mut(&key).and_then(Vec::pop) {
                Some(_) => {}
                // Tolerated: history anomalies (e.g. rows removed outside
                // the change log) must not brick reconstruction.
                None => log_warn!(
                    "No matching record to undo ADD of '{}' {} during reconstruction",
                    change.record_name,
                    change.record_type
                ),
            },
            ChangeOperation::Del => {
                // The recorded row existed before this serial; restore it.
                state.entry(key).or_default().push(ReconstructedRecord {
                    name: change.record_name.clone(),
                    record_type,
                    value: record_value.to_string(),
                    ttl: change.record_ttl,
                    priority: change.record_priority,
                });
            }
        }
    }

    let mut records: Vec<ReconstructedRecord> = state.into_values().flatten().collect();
    sort_records(&mut records);
    Ok(records)
}

/// The record set at `serial`: the live records when it is the current serial,
/// otherwise reconstructed from the journal.
async fn records_at_serial(
    tx: &mut RepositoryTx<'_>,
    zone_id: i32,
    serial: i32,
    current_serial: i32,
) -> Result<Vec<ReconstructedRecord>, ServiceError> {
    if serial == current_serial {
        let mut records: Vec<ReconstructedRecord> =
            RepositoryService::list_records_tx(tx, zone_id, LockLevel::None)
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

/// A serial is diffable only if it is the current serial or has a version.
async fn require_serial(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    serial: i32,
) -> Result<(), ServiceError> {
    if serial == zone.serial {
        return Ok(());
    }
    RepositoryService::get_zone_version_by_serial_tx(tx, zone.id, serial, LockLevel::None)
        .await?
        .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), serial))?;
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

/// Deterministic output order (hash-map iteration order is not).
fn sort_records(records: &mut [ReconstructedRecord]) {
    records.sort_by(|a, b| {
        (&a.name, a.record_type.as_str(), &a.value).cmp(&(
            &b.name,
            b.record_type.as_str(),
            &b.value,
        ))
    });
}

/// Build the zone as it should look after rolling back to `version`: SOA
/// metadata from the version, identity (id/name) and creation time unchanged,
/// serial advanced to `new_serial`.
fn restored_zone_from_version(
    zone: &Zone,
    version: &ZoneVersion,
    new_serial: i32,
) -> Result<Zone, ServiceError> {
    let rname = SoaMailbox::from_encoded(&version.rname)
        .to_email()
        .map_err(|e| ServiceError::internal(format!("Failed to decode version rname: {}", e)))?;

    Ok(Zone {
        id: zone.id,
        name: zone.name.clone(),
        mname: version.mname.clone(),
        rname,
        default_ttl: version.default_ttl,
        serial: new_serial,
        refresh: version.refresh,
        retry: version.retry,
        expire: version.expire,
        dnssec_denial: zone.dnssec_denial,
        minimum_ttl: version.minimum_ttl,
        created_at: zone.created_at,
    })
}

impl ZoneService {
    /// List a zone's versions (serial history), newest serial first. Unless
    /// `all`, signer-only serials (DNSSEC re-signs, rollovers) are skipped —
    /// they hold nothing rollback could restore. Visibility is checked on the
    /// row whose id the queries use, so a same-name recreation cannot swap
    /// the zone in.
    pub async fn list_versions(
        caller: &Caller,
        zone_name: &str,
        limit: Option<u32>,
        offset: Option<u64>,
        all: bool,
    ) -> Result<PaginatedResponse<ZoneVersion>, ServiceError> {
        let zone = Self::get_by_name(caller, zone_name).await?;

        let total = RepositoryService::count_zone_versions(zone.id, !all).await?;
        let effective_limit = limit.unwrap_or(50);
        let items = RepositoryService::list_zone_versions(
            zone.id,
            !all,
            effective_limit,
            offset.unwrap_or(0),
        )
        .await?;

        Ok(crate::pagination::paginated_response(
            items,
            Some(effective_limit),
            offset,
            total,
        ))
    }

    /// Fetch the version at `serial` together with the reconstructed record
    /// set at that serial. Visibility is checked on the row this tx locked, so
    /// a same-name recreation cannot swap the zone in.
    pub async fn get_version(
        caller: &Caller,
        zone_name: &str,
        serial: i32,
    ) -> Result<(ZoneVersion, Vec<ReconstructedRecord>), ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_read_tx("Failed to load version").await?;

        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, lookup_name.as_str(), LockLevel::Shared)
                    .await?;
            if !caller.zone_visible(zone.id) {
                return Err(ServiceError::zone_not_found(zone_name));
            }
            let version = RepositoryService::get_zone_version_by_serial_tx(
                &mut tx,
                zone.id,
                serial,
                LockLevel::None,
            )
            .await?
            .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), serial))?;

            let records = records_at_serial(&mut tx, zone.id, serial, zone.serial).await?;

            Ok::<_, ServiceError>((version, records))
        }
        .await;

        RepositoryService::finish_tx(tx, result, "Failed to load version").await
    }

    /// Compute the record-level difference between two of a zone's serials.
    /// `to_serial` defaults to the zone's current serial when `None`. Each
    /// serial must be the current one or an existing version. Visibility is
    /// checked on the row this tx locked, so a same-name recreation cannot
    /// swap the zone in.
    pub async fn diff_versions(
        caller: &Caller,
        zone_name: &str,
        from_serial: i32,
        to_serial: Option<i32>,
    ) -> Result<VersionDiffResponse, ServiceError> {
        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_read_tx("Failed to diff versions").await?;

        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, lookup_name.as_str(), LockLevel::Shared)
                    .await?;
            if !caller.zone_visible(zone.id) {
                return Err(ServiceError::zone_not_found(zone_name));
            }
            let to_serial = to_serial.unwrap_or(zone.serial);

            require_serial(&mut tx, &zone, from_serial).await?;
            require_serial(&mut tx, &zone, to_serial).await?;

            let from_records =
                records_at_serial(&mut tx, zone.id, from_serial, zone.serial).await?;
            let to_records = records_at_serial(&mut tx, zone.id, to_serial, zone.serial).await?;

            Ok::<_, ServiceError>(VersionDiffResponse {
                from_serial,
                to_serial,
                diff: build_record_diff(&zone, &from_records, &to_records),
            })
        }
        .await;

        RepositoryService::finish_tx(tx, result, "Failed to diff versions").await
    }

    /// Roll a zone back to the state captured at `target_serial`. The record
    /// set and SOA metadata return to that serial's state while the zone's
    /// serial advances to a new value (serials never go backward). The zone
    /// name is not part of a version and is never restored.
    pub async fn rollback(
        caller: &Caller,
        zone_name: &str,
        target_serial: i32,
        dry_run: bool,
    ) -> Result<RollbackZoneResponse, ServiceError> {
        caller.require_global("roll back zones")?;

        let lookup_name = normalize_zone_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to roll back zone").await?;

        let apply_result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, lookup_name.as_str(), LockLevel::Exclusive)
                    .await?;

            if target_serial < 1 || target_serial >= zone.serial {
                return Err(ServiceError::invalid_input(format!(
                    "target serial {} must be less than the current serial {}",
                    target_serial, zone.serial
                )));
            }
            let version = RepositoryService::get_zone_version_by_serial_tx(
                &mut tx,
                zone.id,
                target_serial,
                LockLevel::None,
            )
            .await?
            .ok_or_else(|| ServiceError::version_not_found(zone.name.as_str(), target_serial))?;

            let new_serial = generate_serial(Some(zone.serial))?;
            let restored_zone = restored_zone_from_version(&zone, &version, new_serial)?;
            let soa_changed = zone.soa_metadata_differs(&restored_zone);

            let current_records =
                RepositoryService::list_records_tx(&mut tx, zone.id, LockLevel::Exclusive).await?;
            let target_records =
                reconstruct_records_at_serial(&mut tx, zone.id, target_serial, zone.serial).await?;

            // Diff current vs target, import-Replace style. Protection is
            // evaluated against the restored zone so the restored mname's
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
                        // The DEL + ADD pair preserves the record's identity, so
                        // the mname delete protection cannot be violated.
                        if record.ttl != target.ttl {
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
                            // Protected rows (SOA / restored mname NS) stay.
                            unchanged += 1;
                        }
                    }
                }
            }
            to_add.extend(target_by_key.into_values().flatten());

            // The restored mname must keep a matching apex NS record.
            let deleted_ids: HashSet<i32> = dels.iter().map(|del| del.id).collect();
            let surviving = |record: &&Record| !deleted_ids.contains(&record.id);
            let has_mname = current_records
                .iter()
                .filter(surviving)
                .any(|r| restored_zone.is_mname(&r.record_type, &r.name, &r.value))
                || to_add
                    .iter()
                    .any(|r| restored_zone.is_mname(&r.record_type, &r.name, &r.value));
            if !has_mname {
                // Prefer a restored TTL: the restore is what this serial expresses.
                let candidates = to_add
                    .iter()
                    .map(|r| (&r.record_type, &r.name, r.ttl))
                    .chain(
                        current_records
                            .iter()
                            .filter(surviving)
                            .map(|r| (&r.record_type, &r.name, r.ttl)),
                    );

                to_add.push(ReconstructedRecord {
                    name: OwnerName::apex(),
                    record_type: RecordType::NS,
                    value: restored_zone.mname.clone(),
                    ttl: restored_zone.apex_ns_rrset_ttl(candidates),
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
                    .entry(record.name.clone())
                    .or_default()
                    .push(record.clone());
            }
            let mut to_insert: Vec<Record> = Vec::with_capacity(to_add.len());
            for target in &to_add {
                let same_name = records_by_name.entry(target.name.clone()).or_default();
                validate_record_add_constraints_normalized(
                    same_name,
                    &target.name.clone(),
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
                RepositoryService::create_zone_journal_tx(&mut tx, &changes).await?;
            }

            RecordService::delete_records_with_changes_tx(&mut tx, zone.id, new_serial, &dels)
                .await?;
            RecordService::insert_records_with_changes_tx(&mut tx, zone.id, new_serial, &to_insert)
                .await?;
            // The restored user plane gets fresh signatures; old RRSIGs are
            // never restored (derived journal rows are skipped on reconstruction).
            DnssecService::sign_zone_tx(&mut tx, &restored_zone, new_serial).await?;
            ZoneService::save_version_tx(&mut tx, &restored_zone, new_serial).await?;

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
            if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await
            {
                log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
            }
        }

        Ok(response)
    }
}
