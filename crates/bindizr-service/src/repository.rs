use bindizr_core::dns::name::OwnerName;
use chrono::{DateTime, Utc};

use super::error::{ErrorCode, ServiceError};
pub(crate) use crate::database::repository::RepositoryTx;
use crate::database::{
    get_api_token_repository, get_catalog_zone_repository, get_dnssec_key_repository,
    get_dnssec_policy_repository, get_dnssec_record_repository, get_dnssec_withdrawal_repository,
    get_record_repository, get_secondary_repository, get_token_grant_repository,
    get_tsig_grant_repository, get_tsig_key_repository, get_zone_change_repository,
    get_zone_repository, get_zone_version_repository,
    model::{
        api_token::ApiToken,
        dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_policy::DnssecPolicy,
        dnssec_record::{DnssecRecord, DnssecRecordWithZone},
        record::{Record, RecordWithZone},
        secondary::Secondary,
        token_grant::TokenGrant,
        tsig_grant::TsigGrant,
        tsig_key::TsigKey,
        zone::Zone,
        zone_change::ZoneChange,
        zone_version::ZoneVersion,
    },
    repository as db_repository,
    repository::{DnssecRecordFilter, LockLevel, RecordFilter, ZoneFilter},
};

pub(crate) struct RepositoryService;

impl RepositoryService {
    /// Begin a database transaction and translate any startup error.
    pub(crate) async fn begin_tx(
        internal_msg: &'static str,
    ) -> Result<RepositoryTx<'static>, ServiceError> {
        db_repository::begin_tx().await.map_err(|e| {
            log::error!("Failed to begin transaction: {}", e);
            ServiceError::internal(internal_msg)
        })
    }

    /// Begin a transaction for a caller that only reads; see
    /// [`db_repository::begin_read_tx`].
    pub(crate) async fn begin_read_tx(
        internal_msg: &'static str,
    ) -> Result<RepositoryTx<'static>, ServiceError> {
        db_repository::begin_read_tx().await.map_err(|e| {
            log::error!("Failed to begin transaction: {}", e);
            ServiceError::internal(internal_msg)
        })
    }

    /// Commit on success, roll back on failure. `E` is the caller's error
    /// type, so a front end with its own error taxonomy keeps this one
    /// transaction helper.
    pub(crate) async fn finish_tx<T, E: From<ServiceError>>(
        tx: RepositoryTx<'static>,
        apply_result: Result<T, E>,
        internal_msg: &'static str,
    ) -> Result<T, E> {
        match apply_result {
            Ok(value) => {
                tx.commit().await.map_err(|e| {
                    log::error!("Failed to commit transaction: {}", e);
                    E::from(ServiceError::internal(internal_msg))
                })?;
                Ok(value)
            }
            Err(err) => {
                if let Err(e) = tx.rollback().await {
                    log::error!("Failed to rollback transaction: {}", e);
                }
                Err(err)
            }
        }
    }

    /// Roll back however the work ended: a preview writes only to plan against.
    pub(crate) async fn discard_tx<T, E: From<ServiceError>>(
        tx: RepositoryTx<'static>,
        apply_result: Result<T, E>,
    ) -> Result<T, E> {
        if let Err(e) = tx.rollback().await {
            log::error!("Failed to rollback transaction: {}", e);
        }
        apply_result
    }

    /// Find a zone by name.
    pub(crate) async fn get_zone_by_name(name: &str) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    /// Find a zone by name in the current transaction.
    pub(crate) async fn get_zone_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_name_tx(tx, name, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    /// Find a zone by ID in the current transaction.
    pub(crate) async fn get_zone_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_tx(tx, id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    /// List all zones.
    pub(crate) async fn list_zones() -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    /// List all zones in the current transaction.
    pub(crate) async fn list_zones_tx(
        tx: &mut RepositoryTx<'_>,
        lock_level: LockLevel,
    ) -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .list_all_tx(tx, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    /// List zones matching the filter.
    pub(crate) async fn list_zones_by_filter(
        filter: ZoneFilter,
    ) -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .list_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    /// Count zones matching the filter.
    pub(crate) async fn count_zones_by_filter(filter: ZoneFilter) -> Result<u64, ServiceError> {
        get_zone_repository()
            .count_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count zones: {}", e)))
    }

    /// Probe the zones table to check database connectivity.
    pub(crate) async fn ping() -> Result<(), ServiceError> {
        get_zone_repository()
            .ping()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to reach the zones table: {}", e)))
    }

    /// Mark a zone for DNSSEC withdrawal in the current transaction.
    pub(crate) async fn create_dnssec_withdrawal_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_withdrawal_repository()
            .create_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to record DS withdrawal: {}", e)))
    }

    /// Read a zone's DNSSEC withdrawal marker in the current transaction.
    pub(crate) async fn get_dnssec_withdrawal_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<i32>, ServiceError> {
        get_dnssec_withdrawal_repository()
            .get_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DS withdrawal: {}", e)))
    }

    /// Clear a zone's DNSSEC withdrawal marker in the current transaction.
    pub(crate) async fn delete_dnssec_withdrawal_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_withdrawal_repository()
            .delete_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to clear DS withdrawal: {}", e)))
    }

    /// Store a catalog digest and advance its serial when the digest changes in the current
    /// transaction.
    pub(crate) async fn upsert_catalog_zone_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, ServiceError> {
        get_catalog_zone_repository()
            .upsert_tx(tx, name, digest, base_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update catalog state: {}", e)))
    }

    /// List records for a zone in the current transaction.
    pub(crate) async fn list_records_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .list_tx(tx, zone_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    /// List records at an owner name in a zone in the current transaction.
    pub(crate) async fn list_records_by_name_tx(
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

    /// Find an owner with a DS record but no NS delegation in the current transaction.
    pub(crate) async fn get_ds_name_without_ns_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<String>, ServiceError> {
        get_record_repository()
            .get_ds_name_without_ns_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    /// List records at the requested owner names in a zone in the current transaction.
    pub(crate) async fn list_records_by_names_tx(
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

    /// Insert a batch of records in the current transaction.
    pub(crate) async fn create_records_tx(
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .create_many_tx(tx, records)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create records: {}", e)))
    }

    /// Delete the records with the supplied IDs in the current transaction.
    pub(crate) async fn delete_records_tx(
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), ServiceError> {
        get_record_repository()
            .delete_many_tx(tx, ids)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete records: {}", e)))
    }

    /// Update a record in the current transaction.
    pub(crate) async fn update_record_tx(
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, ServiceError> {
        get_record_repository()
            .update_tx(tx, record)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update record: {}", e)))
    }

    /// List matching records with their zone metadata.
    pub(crate) async fn list_records_by_filter_with_zone(
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, ServiceError> {
        get_record_repository()
            .list_by_filter_with_zone(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    /// Count records matching the filter.
    pub(crate) async fn count_records_by_filter(filter: RecordFilter) -> Result<u64, ServiceError> {
        get_record_repository()
            .count_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count records: {}", e)))
    }

    /// Find a record by ID.
    pub(crate) async fn get_record(record_id: i32) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get(record_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    /// Find a record with its zone metadata.
    pub(crate) async fn get_record_with_zone(
        record_id: i32,
    ) -> Result<Option<RecordWithZone>, ServiceError> {
        get_record_repository()
            .get_with_zone(record_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    /// Find a record by ID in the current transaction.
    pub(crate) async fn get_record_tx(
        tx: &mut RepositoryTx<'_>,
        record_id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get_tx(tx, record_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    /// Insert a batch of journal entries in the current transaction.
    pub(crate) async fn create_zone_changes_tx(
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), ServiceError> {
        get_zone_change_repository()
            .create_many_tx(tx, changes)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create zone changes: {}", e)))
    }

    /// Count journal entries in the interval `(from_serial, to_serial]`.
    pub(crate) async fn count_zone_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<u64, ServiceError> {
        get_zone_change_repository()
            .count_between_serials(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count zone changes: {}", e)))
    }

    /// List journal entries in the interval `(from_serial, to_serial]`.
    pub(crate) async fn list_zone_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        get_zone_change_repository()
            .list_between_serials(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone changes: {}", e)))
    }

    /// Prune one zone's old journal entries, whole serials at a time, in the
    /// current transaction.
    pub(crate) async fn prune_zone_changes_by_zone_id_older_than_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, ServiceError> {
        get_zone_change_repository()
            .prune_by_zone_id_older_than_tx(tx, zone_id, cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to prune zone changes: {}", e)))
    }

    /// Insert or update a zone version in the current transaction.
    pub(crate) async fn upsert_zone_version_tx(
        tx: &mut RepositoryTx<'_>,
        version: ZoneVersion,
    ) -> Result<ZoneVersion, ServiceError> {
        get_zone_version_repository()
            .upsert_tx(tx, version)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to save version: {}", e)))
    }

    /// Prune one zone's old versions, keeping its newest, in the current
    /// transaction.
    pub(crate) async fn prune_zone_versions_by_zone_id_older_than_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, ServiceError> {
        get_zone_version_repository()
            .prune_by_zone_id_older_than_tx(tx, zone_id, cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to prune versions: {}", e)))
    }

    /// Insert a DNSSEC key in the current transaction.
    pub(crate) async fn create_dnssec_key_tx(
        tx: &mut RepositoryTx<'_>,
        key: DnssecKey,
    ) -> Result<DnssecKey, ServiceError> {
        get_dnssec_key_repository()
            .create_tx(tx, key)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create DNSSEC key: {}", e)))
    }

    /// List DNSSEC keys for a zone in the current transaction.
    pub(crate) async fn list_dnssec_keys_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        get_dnssec_key_repository()
            .list_tx(tx, zone_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC keys: {}", e)))
    }

    /// Delete all DNSSEC keys for a zone in the current transaction.
    pub(crate) async fn delete_dnssec_keys_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_key_repository()
            .delete_by_zone_id_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC keys: {}", e)))
    }

    /// List keys in the requested state whose transition deadline has passed.
    pub(crate) async fn list_dnssec_keys_by_state_eligible_before(
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        get_dnssec_key_repository()
            .list_by_state_eligible_before(state, cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC keys: {}", e)))
    }

    /// List zones whose keys have exceeded the policy's ZSK lifetime.
    pub(crate) async fn list_dnssec_key_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
        role: DnssecKeyRole,
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<i32>, ServiceError> {
        get_dnssec_key_repository()
            .list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(role, state, cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC keys: {}", e)))
    }

    /// Count DNSSEC keys in the requested lifecycle state.
    pub(crate) async fn count_dnssec_keys_by_state(
        state: DnssecKeyState,
    ) -> Result<u64, ServiceError> {
        get_dnssec_key_repository()
            .count_by_state(state)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count DNSSEC keys: {}", e)))
    }

    /// Count zones with stored derived DNSSEC records.
    pub(crate) async fn count_dnssec_record_zone_ids() -> Result<u64, ServiceError> {
        get_dnssec_record_repository()
            .count_zone_ids()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count DNSSEC records: {}", e)))
    }

    /// Count signatures due for renewal.
    pub(crate) async fn count_rrsig_dnssec_records_expiring_within_refresh(
        cutoff: DateTime<Utc>,
    ) -> Result<u64, ServiceError> {
        get_dnssec_record_repository()
            .count_expiring_within_refresh(cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count DNSSEC records: {}", e)))
    }

    /// Count signatures whose expiration already passed `cutoff`.
    pub(crate) async fn count_rrsig_dnssec_records_expired_before(
        cutoff: DateTime<Utc>,
    ) -> Result<u64, ServiceError> {
        get_dnssec_record_repository()
            .count_expired_before(cutoff)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count DNSSEC records: {}", e)))
    }

    /// Update a key's lifecycle state and transition deadlines in the current transaction.
    pub(crate) async fn update_dnssec_key_state_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
        state: DnssecKeyState,
        changed_at: DateTime<Utc>,
        eligible_at: DateTime<Utc>,
    ) -> Result<(), ServiceError> {
        get_dnssec_key_repository()
            .update_state_tx(tx, id, state, changed_at, eligible_at)
            .await
            .map_err(|e| {
                ServiceError::internal(format!("failed to update DNSSEC key state: {}", e))
            })
    }

    /// Update the maximum TTL signed by a DNSSEC key in the current transaction.
    pub(crate) async fn update_dnssec_key_max_signed_ttl_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
        max_signed_ttl: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_key_repository()
            .update_max_signed_ttl_tx(tx, id, max_signed_ttl)
            .await
            .map_err(|e| {
                ServiceError::internal(format!("failed to update DNSSEC key max signed TTL: {}", e))
            })
    }

    /// Delete a DNSSEC key by ID in the current transaction.
    pub(crate) async fn delete_dnssec_key_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_key_repository()
            .delete_tx(tx, id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC key: {}", e)))
    }

    /// Insert a batch of derived DNSSEC records in the current transaction.
    pub(crate) async fn create_dnssec_records_tx(
        tx: &mut RepositoryTx<'_>,
        records: &[DnssecRecord],
    ) -> Result<(), ServiceError> {
        get_dnssec_record_repository()
            .create_many_tx(tx, records)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create DNSSEC records: {}", e)))
    }

    /// List derived DNSSEC records for a zone in the current transaction.
    pub(crate) async fn list_dnssec_records_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecRecord>, ServiceError> {
        get_dnssec_record_repository()
            .list_tx(tx, zone_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC records: {}", e)))
    }

    /// Delete the derived DNSSEC records with the supplied IDs in the current transaction.
    pub(crate) async fn delete_dnssec_records_tx(
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), ServiceError> {
        get_dnssec_record_repository()
            .delete_many_tx(tx, ids)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC records: {}", e)))
    }

    /// Delete all derived DNSSEC records for a zone in the current transaction.
    pub(crate) async fn delete_dnssec_records_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_dnssec_record_repository()
            .delete_by_zone_id_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete DNSSEC records: {}", e)))
    }

    /// List matching derived DNSSEC records with their zone metadata.
    pub(crate) async fn list_dnssec_records_by_filter_with_zone(
        filter: DnssecRecordFilter,
    ) -> Result<Vec<DnssecRecordWithZone>, ServiceError> {
        get_dnssec_record_repository()
            .list_by_filter_with_zone(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC records: {}", e)))
    }

    /// Count derived DNSSEC records matching the filter.
    pub(crate) async fn count_dnssec_records_by_filter(
        filter: DnssecRecordFilter,
    ) -> Result<u64, ServiceError> {
        get_dnssec_record_repository()
            .count_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count DNSSEC records: {}", e)))
    }

    /// List zones with signatures due for renewal.
    pub(crate) async fn list_rrsig_zone_ids_expiring_within_refresh(
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<i32>, ServiceError> {
        get_dnssec_record_repository()
            .list_zone_ids_expiring_within_refresh(cutoff)
            .await
            .map_err(|e| {
                ServiceError::internal(format!("failed to find zones needing re-signing: {}", e))
            })
    }

    /// Insert a zone in the current transaction.
    pub(crate) async fn create_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, ServiceError> {
        let name = zone.name.clone();
        get_zone_repository()
            .create_tx(tx, zone)
            .await
            .map_err(|e| {
                // A concurrent create can slip past the service-level name check;
                // surface the UNIQUE(name) backstop as the same conflict error.
                if e.is_unique_violation() {
                    ServiceError::zone_conflict(format!("zone with name '{}' already exists", name))
                } else {
                    ServiceError::internal(format!("failed to create zone: {}", e))
                }
            })
    }

    /// Update a zone in the current transaction.
    pub(crate) async fn update_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, ServiceError> {
        let name = zone.name.clone();
        get_zone_repository()
            .update_tx(tx, zone)
            .await
            .map_err(|e| {
                // A concurrent rename can slip past the service-level name check;
                // surface the UNIQUE(name) backstop as the same conflict error.
                if e.is_unique_violation() {
                    ServiceError::zone_conflict(format!("zone with name '{}' already exists", name))
                } else {
                    ServiceError::internal(format!("failed to update zone: {}", e))
                }
            })
    }

    /// Set only the zone's `dnssec_policy_id`, leaving other columns
    /// untouched; `None` marks the zone unsigned.
    pub(crate) async fn update_zone_dnssec_policy_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        dnssec_policy_id: Option<i32>,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .update_dnssec_policy_id_tx(tx, zone_id, dnssec_policy_id)
            .await
            .map_err(|e| {
                ServiceError::internal(format!("failed to update zone DNSSEC policy: {}", e))
            })
    }

    /// Set or clear a zone's configured parent name servers in the current transaction.
    pub(crate) async fn update_zone_parent_ns_addrs_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        parent_ns_addrs: Option<&str>,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .update_parent_ns_addrs_tx(tx, zone_id, parent_ns_addrs)
            .await
            .map_err(|e| {
                ServiceError::internal(format!(
                    "failed to update zone parent nameserver addresses: {}",
                    e
                ))
            })
    }

    /// Count zones using a DNSSEC policy.
    pub(crate) async fn count_zones_by_dnssec_policy_id(
        dnssec_policy_id: i32,
    ) -> Result<u64, ServiceError> {
        get_zone_repository()
            .count_by_dnssec_policy_id(dnssec_policy_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count zones: {}", e)))
    }

    /// Bump only the zone serial, leaving its other columns untouched.
    pub(crate) async fn update_zone_serial_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .update_serial_tx(tx, zone_id, serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update zone serial: {}", e)))
    }

    /// Delete a zone by ID in the current transaction.
    pub(crate) async fn delete_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .delete_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete zone: {}", e)))
    }

    /// Find a zone version by zone ID and serial.
    pub(crate) async fn get_zone_version_by_serial(
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, ServiceError> {
        get_zone_version_repository()
            .get_by_serial(zone_id, serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load version: {}", e)))
    }

    /// List zone versions in the closed interval `[from_serial, to_serial]`.
    pub(crate) async fn list_zone_versions_in_serial_range(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, ServiceError> {
        get_zone_version_repository()
            .list_in_serial_range(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load versions: {}", e)))
    }

    /// List zone versions for a zone, only those a user change produced when
    /// `user_changes_only`.
    pub(crate) async fn list_zone_versions(
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

    /// Count zone versions using the requested change filter.
    pub(crate) async fn count_zone_versions(
        zone_id: i32,
        user_changes_only: bool,
    ) -> Result<u64, ServiceError> {
        get_zone_version_repository()
            .count(zone_id, user_changes_only)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count versions: {}", e)))
    }

    /// Find a zone version by zone ID and serial in the current transaction.
    pub(crate) async fn get_zone_version_by_serial_tx(
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

    /// List journal entries in the interval `(from_serial, to_serial]` in the current
    /// transaction.
    pub(crate) async fn list_zone_changes_between_serials_tx(
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

    /// Insert a DNSSEC policy.
    pub(crate) async fn create_dnssec_policy(
        policy: DnssecPolicy,
    ) -> Result<DnssecPolicy, ServiceError> {
        let name = policy.name.clone();
        get_dnssec_policy_repository()
            .create(policy)
            .await
            .map_err(|e| {
                // A concurrent create can slip past the service-level name
                // check; surface the UNIQUE(name) backstop as the same conflict.
                if e.is_unique_violation() {
                    ServiceError::dnssec_policy_conflict(&name)
                } else {
                    ServiceError::internal(format!("failed to create DNSSEC policy: {}", e))
                }
            })
    }

    /// Find a DNSSEC policy by ID in the current transaction.
    pub(crate) async fn get_dnssec_policy_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, ServiceError> {
        get_dnssec_policy_repository()
            .get_tx(tx, id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC policy: {}", e)))
    }

    /// Find a DNSSEC policy by name.
    pub(crate) async fn get_dnssec_policy_by_name(
        name: &str,
    ) -> Result<Option<DnssecPolicy>, ServiceError> {
        get_dnssec_policy_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC policy: {}", e)))
    }

    /// Find a DNSSEC policy by name in the current transaction.
    pub(crate) async fn get_dnssec_policy_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, ServiceError> {
        get_dnssec_policy_repository()
            .get_by_name_tx(tx, name, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC policy: {}", e)))
    }

    /// List all DNSSEC policies.
    pub(crate) async fn list_dnssec_policies() -> Result<Vec<DnssecPolicy>, ServiceError> {
        get_dnssec_policy_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load DNSSEC policies: {}", e)))
    }

    /// Update a DNSSEC policy in the current transaction.
    pub(crate) async fn update_dnssec_policy_tx(
        tx: &mut RepositoryTx<'_>,
        policy: DnssecPolicy,
    ) -> Result<DnssecPolicy, ServiceError> {
        get_dnssec_policy_repository()
            .update_tx(tx, policy)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update DNSSEC policy: {}", e)))
    }

    /// Delete a DNSSEC policy by ID.
    pub(crate) async fn delete_dnssec_policy(id: i32) -> Result<(), ServiceError> {
        get_dnssec_policy_repository()
            .delete(id)
            .await
            .map_err(|e| {
                // A zone enabled between the service-level count and this delete
                // trips the FK; surface it as the in-use conflict.
                if e.is_foreign_key_violation() {
                    ServiceError::new(
                        ErrorCode::DnssecPolicyInUse,
                        "DNSSEC policy is still used by signed zones",
                    )
                } else {
                    ServiceError::internal(format!("failed to delete DNSSEC policy: {}", e))
                }
            })
    }

    /// Insert a secondary.
    pub(crate) async fn create_secondary(secondary: Secondary) -> Result<Secondary, ServiceError> {
        let name = secondary.name.clone();
        let address = secondary.address.clone();
        get_secondary_repository()
            .create(secondary)
            .await
            .map_err(|e| {
                // The UNIQUE(name) / UNIQUE(address) backstop for the
                // service-level pre-checks.
                if e.is_unique_violation() {
                    ServiceError::secondary_conflict(format!(
                        "Secondary with name '{}' or address '{}' already exists",
                        name, address
                    ))
                } else {
                    ServiceError::internal(format!("failed to create secondary: {}", e))
                }
            })
    }

    /// Find a secondary by name.
    pub(crate) async fn get_secondary_by_name(
        name: &str,
    ) -> Result<Option<Secondary>, ServiceError> {
        get_secondary_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load secondary: {}", e)))
    }

    /// Find a secondary by name in the current transaction.
    pub(crate) async fn get_secondary_by_name_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Secondary>, ServiceError> {
        get_secondary_repository()
            .get_by_name_tx(tx, name, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load secondary: {}", e)))
    }

    /// Find a secondary by address.
    pub(crate) async fn get_secondary_by_address(
        address: &str,
    ) -> Result<Option<Secondary>, ServiceError> {
        get_secondary_repository()
            .get_by_address(address)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load secondary: {}", e)))
    }

    /// List all secondaries, disabled ones included.
    pub(crate) async fn list_secondaries() -> Result<Vec<Secondary>, ServiceError> {
        get_secondary_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load secondaries: {}", e)))
    }

    /// Write a secondary's address and enabled flag.
    pub(crate) async fn update_secondary_tx(
        tx: &mut RepositoryTx<'_>,
        secondary: Secondary,
    ) -> Result<Secondary, ServiceError> {
        let address = secondary.address.clone();
        get_secondary_repository()
            .update_tx(tx, secondary)
            .await
            .map_err(|e| {
                // The UNIQUE(address) backstop for the service-level pre-check.
                if e.is_unique_violation() {
                    ServiceError::secondary_conflict(format!(
                        "Secondary with address '{}' already exists",
                        address
                    ))
                } else {
                    ServiceError::internal(format!("failed to update secondary: {}", e))
                }
            })
    }

    /// Count the secondaries whose NOTIFY a TSIG key signs.
    pub(crate) async fn count_secondaries_by_notify_tsig_key_id(
        tsig_key_id: i32,
    ) -> Result<u64, ServiceError> {
        get_secondary_repository()
            .count_by_notify_tsig_key_id(tsig_key_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count secondaries: {}", e)))
    }

    /// Delete a secondary by ID.
    pub(crate) async fn delete_secondary(id: i32) -> Result<(), ServiceError> {
        get_secondary_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete secondary: {}", e)))
    }

    /// Insert a TSIG key.
    pub(crate) async fn create_tsig_key(key: TsigKey) -> Result<TsigKey, ServiceError> {
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

    /// Find a TSIG key by ID.
    pub(crate) async fn get_tsig_key(id: i32) -> Result<Option<TsigKey>, ServiceError> {
        get_tsig_key_repository()
            .get(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG key: {}", e)))
    }

    /// Find a TSIG key by name.
    pub(crate) async fn get_tsig_key_by_name(name: &str) -> Result<Option<TsigKey>, ServiceError> {
        get_tsig_key_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG key: {}", e)))
    }

    /// List all TSIG keys.
    pub(crate) async fn list_tsig_keys() -> Result<Vec<TsigKey>, ServiceError> {
        get_tsig_key_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG keys: {}", e)))
    }

    /// Delete a TSIG key by ID.
    pub(crate) async fn delete_tsig_key(id: i32) -> Result<(), ServiceError> {
        get_tsig_key_repository().delete(id).await.map_err(|e| {
            // A grant or secondary that took the key between the service-level
            // counts and this delete trips the FK: the same in-use conflict.
            if e.is_foreign_key_violation() {
                ServiceError::new(
                    ErrorCode::TsigKeyInUse,
                    "TSIG key is still referenced by zone TSIG grants or secondaries",
                )
            } else {
                ServiceError::internal(format!("failed to delete TSIG key: {}", e))
            }
        })
    }

    /// Insert a TSIG grant.
    pub(crate) async fn create_tsig_grant(grant: TsigGrant) -> Result<TsigGrant, ServiceError> {
        get_tsig_grant_repository()
            .create(grant)
            .await
            .map_err(|e| {
                // The zone or key can be deleted between the service-level
                // existence checks and this insert; the FK reports it.
                if e.is_foreign_key_violation() {
                    ServiceError::new(ErrorCode::ZoneNotFound, "Zone or TSIG key no longer exists")
                } else {
                    ServiceError::internal(format!("failed to create TSIG grant: {}", e))
                }
            })
    }

    /// Find a TSIG grant by ID.
    pub(crate) async fn get_tsig_grant(id: i32) -> Result<Option<TsigGrant>, ServiceError> {
        get_tsig_grant_repository()
            .get(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG grant: {}", e)))
    }

    /// List TSIG grants for a zone.
    pub(crate) async fn list_tsig_grants_by_zone_id(
        zone_id: i32,
    ) -> Result<Vec<TsigGrant>, ServiceError> {
        get_tsig_grant_repository()
            .list_by_zone_id(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG grants: {}", e)))
    }

    /// List TSIG grants for a TSIG key in a zone in the current transaction.
    pub(crate) async fn list_tsig_grants_by_zone_id_and_key_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<TsigGrant>, ServiceError> {
        get_tsig_grant_repository()
            .list_by_zone_id_and_key_id_tx(tx, zone_id, tsig_key_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG grants: {}", e)))
    }

    /// List TSIG grants for a TSIG key.
    pub(crate) async fn list_tsig_grants_by_key_id(
        tsig_key_id: i32,
    ) -> Result<Vec<TsigGrant>, ServiceError> {
        get_tsig_grant_repository()
            .list_by_key_id(tsig_key_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG grants: {}", e)))
    }

    /// Count TSIG grants for a TSIG key.
    pub(crate) async fn count_tsig_grants_by_key_id(tsig_key_id: i32) -> Result<u64, ServiceError> {
        get_tsig_grant_repository()
            .count_by_key_id(tsig_key_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count TSIG grants: {}", e)))
    }

    /// Delete a TSIG grant by ID.
    pub(crate) async fn delete_tsig_grant(id: i32) -> Result<(), ServiceError> {
        get_tsig_grant_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete TSIG grant: {}", e)))
    }

    /// Delete every grant a TSIG key holds in a zone, returning how many went.
    pub(crate) async fn delete_tsig_grants_by_key_id_and_zone_id(
        tsig_key_id: i32,
        zone_id: i32,
    ) -> Result<u64, ServiceError> {
        get_tsig_grant_repository()
            .delete_by_key_id_and_zone_id(tsig_key_id, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete TSIG grants: {}", e)))
    }

    /// Insert a token grant.
    pub(crate) async fn create_token_grant(grant: TokenGrant) -> Result<TokenGrant, ServiceError> {
        get_token_grant_repository()
            .create(grant)
            .await
            .map_err(|e| {
                // The zone or token can be deleted between the service-level
                // existence checks and this insert; the FK reports it.
                if e.is_foreign_key_violation() {
                    ServiceError::new(ErrorCode::ZoneNotFound, "Zone or token no longer exists")
                } else {
                    ServiceError::internal(format!("failed to create token grant: {}", e))
                }
            })
    }

    /// Find a token grant by ID.
    pub(crate) async fn get_token_grant(id: i32) -> Result<Option<TokenGrant>, ServiceError> {
        get_token_grant_repository()
            .get(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token grant: {}", e)))
    }

    /// List token grants for a zone.
    pub(crate) async fn list_token_grants_by_zone_id(
        zone_id: i32,
    ) -> Result<Vec<TokenGrant>, ServiceError> {
        get_token_grant_repository()
            .list_by_zone_id(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token grants: {}", e)))
    }

    /// List token grants for an API token.
    pub(crate) async fn list_token_grants_by_token_id(
        api_token_id: i32,
    ) -> Result<Vec<TokenGrant>, ServiceError> {
        get_token_grant_repository()
            .list_by_token_id(api_token_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token grants: {}", e)))
    }

    /// List token grants for an API token in a zone in the current transaction.
    pub(crate) async fn list_token_grants_by_zone_id_and_token_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<TokenGrant>, ServiceError> {
        get_token_grant_repository()
            .list_by_zone_id_and_token_id_tx(tx, zone_id, api_token_id, lock_level)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token grants: {}", e)))
    }

    /// Delete a token grant by ID.
    pub(crate) async fn delete_token_grant(id: i32) -> Result<(), ServiceError> {
        get_token_grant_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete token grant: {}", e)))
    }

    /// Delete every grant a token holds in a zone, returning how many went.
    pub(crate) async fn delete_token_grants_by_token_id_and_zone_id(
        api_token_id: i32,
        zone_id: i32,
    ) -> Result<u64, ServiceError> {
        get_token_grant_repository()
            .delete_by_token_id_and_zone_id(api_token_id, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete token grants: {}", e)))
    }

    /// Insert an API token.
    pub(crate) async fn create_api_token(token: ApiToken) -> Result<ApiToken, ServiceError> {
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

    /// Find an API token by name.
    pub(crate) async fn get_api_token_by_name(
        name: &str,
    ) -> Result<Option<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token: {}", e)))
    }

    /// List all API tokens.
    pub(crate) async fn list_api_tokens() -> Result<Vec<ApiToken>, ServiceError> {
        get_api_token_repository()
            .list_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load tokens: {}", e)))
    }

    /// Find an API token by its stored token hash.
    pub(crate) async fn get_api_token_by_token(
        token: &str,
    ) -> Result<Option<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_by_token(token)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token: {}", e)))
    }

    /// Update an API token.
    pub(crate) async fn update_api_token(token: ApiToken) -> Result<ApiToken, ServiceError> {
        get_api_token_repository()
            .update(token)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to update token: {}", e)))
    }

    /// Delete an API token by ID.
    pub(crate) async fn delete_api_token(id: i32) -> Result<(), ServiceError> {
        get_api_token_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to delete token: {}", e)))
    }
}
