use bindizr_core::dns::name::OwnerName;

use super::error::{ErrorCode, ServiceError};
pub(crate) use crate::database::repository::RepositoryTx;
use crate::{
    database::{
        error::DatabaseError,
        get_api_token_repository, get_catalog_zone_state_repository, get_record_repository,
        get_tsig_key_repository, get_zone_change_repository, get_zone_repository,
        get_zone_snapshot_repository, get_zone_token_policy_repository,
        get_zone_tsig_policy_repository,
        model::{
            api_token::ApiToken,
            record::{Record, RecordWithZone},
            tsig_key::TsigKey,
            zone::Zone,
            zone_change::ZoneChange,
            zone_snapshot::ZoneSnapshot,
            zone_token_policy::ZoneTokenPolicy,
            zone_tsig_policy::ZoneTsigPolicy,
        },
        repository as db_repository,
        repository::{RecordFilter, ZoneFilter},
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
    ) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_name_tx(tx, name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    pub(super) async fn get_zone_by_id_tx(
        tx: &mut RepositoryTx<'_>,
        id: i32,
    ) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_id_tx(tx, id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone: {}", e)))
    }

    pub(super) async fn get_all_zones() -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .get_all()
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    pub(super) async fn get_all_zones_tx(
        tx: &mut RepositoryTx<'_>,
    ) -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .get_all_tx(tx)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zones: {}", e)))
    }

    pub(super) async fn get_zones_by_filter(filter: ZoneFilter) -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_filter(filter)
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

    pub(super) async fn update_catalog_serial_for_signature_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
        signature: &str,
        base_serial: i32,
    ) -> Result<i32, ServiceError> {
        get_catalog_zone_state_repository()
            .update_serial_for_signature_tx(tx, name, signature, base_serial)
            .await
            .map(|state| state.serial)
            .map_err(|e| ServiceError::internal(format!("failed to update catalog state: {}", e)))
    }

    pub(super) async fn get_records_by_zone_id(zone_id: i32) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_by_zone_id(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn get_records_by_zone_ids(
        zone_ids: &[i32],
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_by_zone_ids(zone_ids)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn get_records_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_by_zone_id_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn get_records_by_zone_id_and_name_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &OwnerName,
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_by_zone_id_and_name_tx(tx, zone_id, name)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn get_records_by_zone_id_and_names_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        names: &[OwnerName],
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_by_zone_id_and_names_tx(tx, zone_id, names)
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

    pub(super) async fn get_records_by_filter_with_zone(
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, ServiceError> {
        get_record_repository()
            .get_by_filter_with_zone(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load records: {}", e)))
    }

    pub(super) async fn count_records_by_filter(filter: RecordFilter) -> Result<u64, ServiceError> {
        get_record_repository()
            .count_by_filter(filter)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count records: {}", e)))
    }

    pub(super) async fn get_record_by_id(record_id: i32) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get_by_id(record_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    pub(super) async fn get_record_by_id_with_zone(
        record_id: i32,
    ) -> Result<Option<RecordWithZone>, ServiceError> {
        get_record_repository()
            .get_by_id_with_zone(record_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    pub(super) async fn get_record_by_id_tx(
        tx: &mut RepositoryTx<'_>,
        record_id: i32,
    ) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get_by_id_tx(tx, record_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load record: {}", e)))
    }

    pub(super) async fn create_zone_changes_tx(
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), ServiceError> {
        get_zone_change_repository()
            .create_many_tx(tx, changes)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to create zone changes: {}", e)))
    }

    pub(super) async fn get_zone_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        get_zone_change_repository()
            .get_changes_between_serials(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load zone changes: {}", e)))
    }

    pub(super) async fn upsert_zone_snapshot_tx(
        tx: &mut RepositoryTx<'_>,
        snapshot: ZoneSnapshot,
    ) -> Result<ZoneSnapshot, ServiceError> {
        get_zone_snapshot_repository()
            .upsert_tx(tx, snapshot)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to save snapshot: {}", e)))
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

    pub(super) async fn get_zone_snapshot_by_serial(
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneSnapshot>, ServiceError> {
        get_zone_snapshot_repository()
            .get_by_zone_id_and_serial(zone_id, serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load snapshot: {}", e)))
    }

    pub(super) async fn get_zone_snapshots_in_range(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneSnapshot>, ServiceError> {
        get_zone_snapshot_repository()
            .get_by_zone_id_in_serial_range(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load snapshots: {}", e)))
    }

    pub(super) async fn list_zone_snapshots(
        zone_id: i32,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ZoneSnapshot>, ServiceError> {
        get_zone_snapshot_repository()
            .list_by_zone_id(zone_id, limit, offset)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to list snapshots: {}", e)))
    }

    pub(super) async fn count_zone_snapshots(zone_id: i32) -> Result<u64, ServiceError> {
        get_zone_snapshot_repository()
            .count_by_zone_id(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to count snapshots: {}", e)))
    }

    pub(super) async fn get_zone_snapshot_by_serial_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneSnapshot>, ServiceError> {
        get_zone_snapshot_repository()
            .get_by_zone_id_and_serial_tx(tx, zone_id, serial)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load snapshot: {}", e)))
    }

    pub(super) async fn get_zone_changes_between_serials_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        get_zone_change_repository()
            .get_changes_between_serials_tx(tx, zone_id, from_serial, to_serial)
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

    pub(super) async fn get_all_tsig_keys() -> Result<Vec<TsigKey>, ServiceError> {
        get_tsig_key_repository()
            .get_all()
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

    pub(super) async fn get_zone_tsig_policy_by_id(
        id: i32,
    ) -> Result<Option<ZoneTsigPolicy>, ServiceError> {
        get_zone_tsig_policy_repository()
            .get_by_id(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG policy: {}", e)))
    }

    pub(super) async fn get_zone_tsig_policies_by_zone_id(
        zone_id: i32,
    ) -> Result<Vec<ZoneTsigPolicy>, ServiceError> {
        get_zone_tsig_policy_repository()
            .get_by_zone_id(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load TSIG policies: {}", e)))
    }

    pub(super) async fn get_zone_tsig_policies_by_zone_and_key_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
    ) -> Result<Vec<ZoneTsigPolicy>, ServiceError> {
        get_zone_tsig_policy_repository()
            .get_by_zone_and_key_tx(tx, zone_id, tsig_key_id)
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

    pub(super) async fn get_zone_token_policy_by_id(
        id: i32,
    ) -> Result<Option<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .get_by_id(id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token policy: {}", e)))
    }

    pub(super) async fn get_zone_token_policies_by_zone_id(
        zone_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .get_by_zone_id(zone_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token policies: {}", e)))
    }

    pub(super) async fn get_zone_token_policies_by_token_id(
        api_token_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .get_by_token_id(api_token_id)
            .await
            .map_err(|e| ServiceError::internal(format!("failed to load token policies: {}", e)))
    }

    pub(super) async fn get_zone_token_policies_by_zone_and_token_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
    ) -> Result<Vec<ZoneTokenPolicy>, ServiceError> {
        get_zone_token_policy_repository()
            .get_by_zone_and_token_tx(tx, zone_id, api_token_id)
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

    pub(super) async fn get_all_api_tokens() -> Result<Vec<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_all()
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
