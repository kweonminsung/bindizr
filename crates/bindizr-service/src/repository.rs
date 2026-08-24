use bindizr_core::dns::name::OwnerName;
use chrono::{DateTime, Utc};

use super::error::{ErrorCode, ServiceError};
pub(crate) use crate::database::repository::RepositoryTx;
use crate::{
    database::{
        error::DatabaseError,
        get_api_token_repository, get_catalog_zone_state_repository, get_dnssec_key_repository,
        get_dnssec_record_repository, get_record_repository, get_tsig_key_repository,
        get_zone_change_repository, get_zone_repository, get_zone_token_policy_repository,
        get_zone_tsig_policy_repository, get_zone_version_repository,
        model::{
            api_token::ApiToken,
            dnssec_key::{DnssecKey, DnssecKeyState},
            dnssec_record::DnssecRecord,
            record::{Record, RecordWithZone},
            tsig_key::TsigKey,
            zone::{DnssecDenial, Zone},
            zone_change::ZoneChange,
            zone_token_policy::ZoneTokenPolicy,
            zone_tsig_policy::ZoneTsigPolicy,
            zone_version::ZoneVersion,
        },
        repository as db_repository,
        repository::{LockLevel, RecordFilter, ZoneFilter},
    },
    log_error,
};

pub(super) struct RepositoryService;

/// Map a zone insert/update failure: the UNIQUE(name) backstop catches
/// check-then-act races on the zone name and becomes the same conflict error
/// the service-level pre-check produces; anything else stays internal.
fn zone_name_race_error(name: &str, action: &str, e: DatabaseError) -> ServiceError {
    if e.is_unique_violation() {
        ServiceError::zone_conflict(format!("zone with name '{}' already exists", name))
    } else {
        ServiceError::internal(format!("failed to {} zone: {}", action, e))
    }
}

impl RepositoryService {
    pub(super) async fn begin_tx(
        internal_msg: &'static str,
    ) -> Result<RepositoryTx<'static>, ServiceError> {
        db_repository::begin_transaction().await.map_err(|e| {
            log_error!("Failed to begin transaction: {}", e);
            ServiceError::internal(internal_msg.to_string())
        })
    }

    /// Commit on success, roll back on failure. `E` is the caller's error
    /// type, so a front end with its own error taxonomy keeps this one
    /// transaction helper.
    pub(super) async fn finish_tx<T, E: From<ServiceError>>(
        tx: RepositoryTx<'static>,
        apply_result: Result<T, E>,
        internal_msg: &'static str,
    ) -> Result<T, E> {
        match apply_result {
            Ok(value) => {
                tx.commit().await.map_err(|e| {
                    log_error!("Failed to commit transaction: {}", e);
                    E::from(ServiceError::internal(internal_msg.to_string()))
                })?;
                Ok(value)
            }
            Err(err) => {
                if let Err(e) = tx.rollback().await {
                    log_error!("Failed to rollback transaction: {}", e);
                }
                Err(err)
            }
        }
    }

    pub(super) async fn get_zone_by_name(name: &str) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    pub(super) async fn get_zone_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_name_tx(tx, name, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    pub(super) async fn get_zone_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_tx(tx, id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    pub(super) async fn list_zones() -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    pub(super) async fn list_zones_tx(
        tx: &mut RepositoryTx<'_>,
        lock_level: LockLevel,
    ) -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .list_all_tx(tx, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    pub(super) async fn list_zones_by_filter(
        filter: ZoneFilter,
    ) -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .list_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    pub(super) async fn count_zones_by_filter(filter: ZoneFilter) -> Result<u64, ServiceError> {
        get_zone_repository()
            .count_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count zones: {}", e)))
    }

    pub(super) async fn ping_zones() -> Result<(), ServiceError> {
        get_zone_repository()
            .ping()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to reach the zones table: {}", e)))
    }

    pub(super) async fn upsert_catalog_zone_state_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, ServiceError> {
        get_catalog_zone_state_repository()
            .upsert_tx(tx, name, digest, base_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update catalog state: {}", e)))
    }

    pub(super) async fn list_records(zone_id: i32) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .list(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn list_records_by_zone_ids(
        zone_ids: &[i32],
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .list_by_zone_ids(zone_ids)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn list_records_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .list_tx(tx, zone_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn list_records_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &OwnerName,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .list_by_name_tx(tx, zone_id, name, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn list_records_by_names_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        names: &[OwnerName],
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .list_by_names_tx(tx, zone_id, names, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn create_record_tx(
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, ServiceError> {
        get_record_repository()
            .create_tx(tx, record)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create record: {}", e)))
    }

    pub(super) async fn create_records_tx(
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .create_many_tx(tx, records)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create records: {}", e)))
    }

    pub(super) async fn delete_records_tx(
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), ServiceError> {
        get_record_repository()
            .delete_many_tx(tx, ids)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete records: {}", e)))
    }

    pub(super) async fn update_record_tx(
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, ServiceError> {
        get_record_repository()
            .update_tx(tx, record)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update record: {}", e)))
    }

    pub(super) async fn list_records_by_filter_with_zone(
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, ServiceError> {
        get_record_repository()
            .list_by_filter_with_zone(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn count_records_by_filter(filter: RecordFilter) -> Result<u64, ServiceError> {
        get_record_repository()
            .count_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count records: {}", e)))
    }

    pub(super) async fn get_record(record_id: i32) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get(record_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    pub(super) async fn get_record_with_zone(
        record_id: i32,
    ) -> Result<Option<RecordWithZone>, ServiceError> {
        get_record_repository()
            .get_with_zone(record_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    pub(super) async fn get_record_tx(
        tx: &mut RepositoryTx<'_>,
        record_id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get_tx(tx, record_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    pub(super) async fn create_zone_journal_tx(
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), ServiceError> {
        get_zone_change_repository()
            .create_many_tx(tx, changes)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create zone changes: {}", e)))
    }

    pub(super) async fn list_zone_journal_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        get_zone_change_repository()
            .list_between_serials(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone changes: {}", e)))
    }

    pub(super) async fn prune_zone_journal_older_than(
        cutoff: DateTime<Utc>,
    ) -> Result<u64, ServiceError> {
        get_zone_change_repository()
            .prune_older_than(cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to prune zone changes: {}", e)))
    }

    pub(super) async fn upsert_zone_version_tx(
        tx: &mut RepositoryTx<'_>,
        version: ZoneVersion,
    ) -> Result<ZoneVersion, ServiceError> {
        get_zone_version_repository()
            .upsert_tx(tx, version)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to save version: {}", e)))
    }

    pub(super) async fn prune_zone_versions_older_than(
        cutoff: DateTime<Utc>,
    ) -> Result<u64, ServiceError> {
        get_zone_version_repository()
            .prune_older_than(cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to prune versions: {}", e)))
    }

    pub(super) async fn create_dnssec_key_tx(
        tx: &mut RepositoryTx<'_>,
        key: DnssecKey,
    ) -> Result<DnssecKey, ServiceError> {
        get_dnssec_key_repository()
            .create_tx(tx, key)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create DNSSEC key: {}", e)))
    }

    pub(super) async fn list_dnssec_keys_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        get_dnssec_key_repository()
            .list_tx(tx, zone_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC keys: {}", e)))
    }

    pub(super) async fn delete_dnssec_keys_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_key_repository()
            .delete_by_zone_id_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC keys: {}", e)))
    }

    pub(super) async fn list_dnssec_keys_by_state_entered_before(
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        get_dnssec_key_repository()
            .list_by_state_entered_before(state, cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC keys: {}", e)))
    }

    pub(super) async fn update_dnssec_key_state_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
        state: DnssecKeyState,
        changed_at: DateTime<Utc>,
    ) -> Result<(), ServiceError> {
        get_dnssec_key_repository()
            .update_state_tx(tx, id, state, changed_at)
            .await
            .map_err(|e| {
                ServiceError::internal(format!("failed to update DNSSEC key state: {}", e))
            })
    }

    pub(super) async fn delete_dnssec_key_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_key_repository()
            .delete_tx(tx, id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC key: {}", e)))
    }

    pub(super) async fn create_dnssec_records_tx(
        tx: &mut RepositoryTx<'_>,
        records: &[DnssecRecord],
    ) -> Result<(), ServiceError> {
        get_dnssec_record_repository()
            .create_many_tx(tx, records)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create DNSSEC records: {}", e)))
    }

    pub(super) async fn list_dnssec_records(
        zone_id: i32,
    ) -> Result<Vec<DnssecRecord>, ServiceError> {
        get_dnssec_record_repository()
            .list(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC records: {}", e)))
    }

    pub(super) async fn list_dnssec_records_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecRecord>, ServiceError> {
        get_dnssec_record_repository()
            .list_tx(tx, zone_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC records: {}", e)))
    }

    pub(super) async fn delete_dnssec_records_tx(
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), ServiceError> {
        get_dnssec_record_repository()
            .delete_many_tx(tx, ids)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC records: {}", e)))
    }

    pub(super) async fn delete_dnssec_records_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_record_repository()
            .delete_by_zone_id_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC records: {}", e)))
    }

    pub(super) async fn list_rrsig_zone_ids_expiring_before(
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<i32>, ServiceError> {
        get_dnssec_record_repository()
            .list_zone_ids_expiring_before(cutoff)
            .await
            .map_err(|e| {
                ServiceError::internal(format!("failed to find zones needing re-signing: {}", e))
            })
    }

    pub(super) async fn create_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, ServiceError> {
        let name = zone.name.clone();
        get_zone_repository()
            .create_tx(tx, zone)
            .await
            .map_err(|e| zone_name_race_error(name.as_str(), "create", e))
    }

    pub(super) async fn update_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, ServiceError> {
        let name = zone.name.clone();
        get_zone_repository()
            .update_tx(tx, zone)
            .await
            .map_err(|e| zone_name_race_error(name.as_str(), "update", e))
    }

    /// Set only the zone's `dnssec_denial` mode, leaving other columns untouched.
    pub(super) async fn update_zone_dnssec_denial_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        denial: DnssecDenial,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .update_dnssec_denial_tx(tx, zone_id, denial)
            .await
            .map_err(|e| {
                ServiceError::internal(format!("failed to update zone DNSSEC options: {}", e))
            })
    }

    /// Bump only the zone serial, leaving its other columns untouched.
    pub(super) async fn update_zone_serial_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .update_serial_tx(tx, zone_id, serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update zone serial: {}", e)))
    }

    pub(super) async fn delete_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .delete_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete zone: {}", e)))
    }

    pub(super) async fn get_zone_version_by_serial(
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, ServiceError> {
        get_zone_version_repository()
            .get_by_serial(zone_id, serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load version: {}", e)))
    }

    pub(super) async fn list_zone_versions_in_serial_range(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, ServiceError> {
        get_zone_version_repository()
            .list_in_serial_range(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load versions: {}", e)))
    }

    pub(super) async fn list_zone_versions(
        zone_id: i32,
        user_changes_only: bool,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ZoneVersion>, ServiceError> {
        get_zone_version_repository()
            .list(zone_id, user_changes_only, limit, offset)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to list versions: {}", e)))
    }

    pub(super) async fn count_zone_versions(
        zone_id: i32,
        user_changes_only: bool,
    ) -> Result<u64, ServiceError> {
        get_zone_version_repository()
            .count(zone_id, user_changes_only)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count versions: {}", e)))
    }

    pub(super) async fn get_zone_version_by_serial_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
        lock_level: LockLevel,
    ) -> Result<Option<ZoneVersion>, ServiceError> {
        get_zone_version_repository()
            .get_by_serial_tx(tx, zone_id, serial, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load version: {}", e)))
    }

    pub(super) async fn list_zone_journal_between_serials_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        get_zone_change_repository()
            .list_between_serials_tx(tx, zone_id, from_serial, to_serial, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone changes: {}", e)))
    }

    pub(super) async fn create_tsig_key(key: TsigKey) -> Result<TsigKey, ServiceError> {
        let name = key.name.clone();
        get_tsig_key_repository().create(key).await.map_err(|e| {
            // A concurrent create can slip past the service-level name check;
            // surface the UNIQUE(name) backstop as the same conflict error.
            if e.is_unique_violation() {
                ServiceError::tsig_key_conflict(&name)
            } else {
                ServiceError::internal(format!("failed to create TSIG key: {}", e))
            }
        })
    }

    pub(super) async fn get_tsig_key_by_name(name: &str) -> Result<Option<TsigKey>, ServiceError> {
        get_tsig_key_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG key: {}", e)))
    }

    pub(super) async fn list_tsig_keys() -> Result<Vec<TsigKey>, ServiceError> {
        get_tsig_key_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG keys: {}", e)))
    }

    pub(super) async fn delete_tsig_key(id: i32) -> Result<(), ServiceError> {
        get_tsig_key_repository().delete(id).await.map_err(|e| {
            // A policy created between the service-level count and this delete
            // trips the FK; surface it as the in-use conflict.
            if e.is_foreign_key_violation() {
                ServiceError::new(
                    ErrorCode::TsigKeyInUse,
                    "TSIG key is still referenced by zone TSIG policies",
                )
            } else {
                ServiceError::internal(format!("failed to delete TSIG key: {}", e))
            }
        })
    }

    pub(super) async fn create_zone_tsig_policy(
        policy: ZoneTsigPolicy,
    ) -> Result<ZoneTsigPolicy, ServiceError> {
        get_zone_tsig_policy_repository()
            .create(policy)
            .await
            .map_err(|e| {
                // The zone or key can be deleted between the service-level
                // existence checks and this insert; the FK reports it.
                if e.is_foreign_key_violation() {
                    ServiceError::new(ErrorCode::ZoneNotFound, "Zone or TSIG key no longer exists")
                } else {
                    ServiceError::internal(format!("failed to create TSIG policy: {}", e))
                }
            })
    }

    pub(super) async fn get_zone_tsig_policy(
        id: i32,
    ) -> Result<Option<ZoneTsigPolicy>, ServiceError> {
        get_zone_tsig_policy_repository()
            .get(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG policy: {}", e)))
    }

    pub(super) async fn list_zone_tsig_policies(
        zone_id: i32,
    ) -> Result<Vec<ZoneTsigPolicy>, ServiceError> {
        get_zone_tsig_policy_repository()
            .list(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG policies: {}", e)))
    }

    pub(super) async fn list_zone_tsig_policies_by_zone_id_and_key_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneTsigPolicy>, ServiceError> {
        get_zone_tsig_policy_repository()
            .list_by_zone_id_and_key_id_tx(tx, zone_id, tsig_key_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG policies: {}", e)))
    }

    pub(super) async fn count_zone_tsig_policies_by_key_id(
        tsig_key_id: i32,
    ) -> Result<u64, ServiceError> {
        get_zone_tsig_policy_repository()
            .count_by_key_id(tsig_key_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count TSIG policies: {}", e)))
    }

    pub(super) async fn delete_zone_tsig_policy(id: i32) -> Result<(), ServiceError> {
        get_zone_tsig_policy_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete TSIG policy: {}", e)))
    }

    pub(super) async fn create_zone_token_policy(
        policy: ZoneTokenPolicy,
    ) -> Result<ZoneTokenPolicy, ServiceError> {
        get_zone_token_policy_repository()
            .create(policy)
            .await
            .map_err(|e| {
                // The zone or token can be deleted between the service-level
                // existence checks and this insert; the FK reports it.
                if e.is_foreign_key_violation() {
                    ServiceError::new(ErrorCode::ZoneNotFound, "Zone or token no longer exists")
                } else {
                    ServiceError::internal(format!("failed to create token policy: {}", e))
                }
            })
    }

    pub(super) async fn get_zone_token_policy(
        id: i32,
    ) -> Result<Option<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .get(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token policy: {}", e)))
    }

    pub(super) async fn list_zone_token_policies(
        zone_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .list(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token policies: {}", e)))
    }

    pub(super) async fn list_zone_token_policies_by_token_id(
        api_token_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .list_by_token_id(api_token_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token policies: {}", e)))
    }

    pub(super) async fn list_zone_token_policies_by_zone_id_and_token_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .list_by_zone_id_and_token_id_tx(tx, zone_id, api_token_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token policies: {}", e)))
    }

    pub(super) async fn delete_zone_token_policy(id: i32) -> Result<(), ServiceError> {
        get_zone_token_policy_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete token policy: {}", e)))
    }

    pub(super) async fn create_api_token(token: ApiToken) -> Result<ApiToken, ServiceError> {
        let name = token.name.clone();
        get_api_token_repository().create(token).await.map_err(|e| {
            // A concurrent create can slip past the service-level name check;
            // surface the UNIQUE(name) backstop as the same conflict error.
            if e.is_unique_violation() {
                ServiceError::token_conflict(&name)
            } else {
                ServiceError::internal(format!("failed to create token: {}", e))
            }
        })
    }

    pub(super) async fn get_api_token_by_name(
        name: &str,
    ) -> Result<Option<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token: {}", e)))
    }

    pub(super) async fn list_api_tokens() -> Result<Vec<ApiToken>, ServiceError> {
        get_api_token_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load tokens: {}", e)))
    }

    pub(super) async fn get_api_token_by_token(
        token: &str,
    ) -> Result<Option<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_by_token(token)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token: {}", e)))
    }

    pub(super) async fn update_api_token(token: ApiToken) -> Result<ApiToken, ServiceError> {
        get_api_token_repository()
            .update(token)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update token: {}", e)))
    }

    pub(super) async fn delete_api_token(id: i32) -> Result<(), ServiceError> {
        get_api_token_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete token: {}", e)))
    }
}
