use crate::database::{
    get_api_token_repository, get_record_repository, get_zone_change_repository,
    get_zone_repository, get_zone_snapshot_repository,
    model::{
        api_token::ApiToken,
        record::{Record, RecordType},
        zone::Zone,
        zone_change::ZoneChange,
        zone_snapshot::ZoneSnapshot,
    },
};

use crate::log_error;

use crate::database::repository as db_repository;

pub use crate::database::repository::RepositoryTx;

use super::error::ServiceError;

pub struct RepositoryService;

#[allow(dead_code)]
impl RepositoryService {
    pub async fn begin_tx(
        internal_msg: &'static str,
    ) -> Result<RepositoryTx<'static>, ServiceError> {
        db_repository::begin_transaction().await.map_err(|e| {
            log_error!("Failed to begin transaction: {}", e);
            ServiceError::Internal(internal_msg.to_string())
        })
    }

    pub async fn finish_tx<T>(
        tx: RepositoryTx<'static>,
        apply_result: Result<T, ServiceError>,
        internal_msg: &'static str,
    ) -> Result<T, ServiceError> {
        match apply_result {
            Ok(value) => {
                tx.commit().await.map_err(|e| {
                    log_error!("Failed to commit transaction: {}", e);
                    ServiceError::Internal(internal_msg.to_string())
                })?;
                Ok(value)
            }
            Err(err) => {
                tx.rollback().await.map_err(|e| {
                    log_error!("Failed to rollback transaction: {}", e);
                    ServiceError::Internal(internal_msg.to_string())
                })?;
                Err(err)
            }
        }
    }

    pub async fn get_zone_by_name(name: &str) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_name(name)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load zone: {}", e)))
    }

    pub async fn get_zone_by_name_for_update_tx(
        tx: &mut RepositoryTx<'_>,
        name: &str,
    ) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_name_for_update_tx(tx, name)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load zone: {}", e)))
    }

    pub async fn get_zone_by_id(id: i32) -> Result<Option<Zone>, ServiceError> {
        get_zone_repository()
            .get_by_id(id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load zone: {}", e)))
    }

    pub async fn get_all_zones() -> Result<Vec<Zone>, ServiceError> {
        get_zone_repository()
            .get_all()
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load zones: {}", e)))
    }

    pub async fn update_zone(zone: Zone) -> Result<Zone, ServiceError> {
        get_zone_repository()
            .update(zone)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to update zone: {}", e)))
    }

    pub async fn create_zone(zone: Zone) -> Result<Zone, ServiceError> {
        get_zone_repository()
            .create(zone)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to create zone: {}", e)))
    }

    pub async fn delete_zone(zone_id: i32) -> Result<(), ServiceError> {
        get_zone_repository()
            .delete(zone_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to delete zone: {}", e)))
    }

    pub async fn get_records_by_zone_id(zone_id: i32) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_by_zone_id(zone_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load records: {}", e)))
    }

    pub async fn get_records_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_by_zone_id_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load records: {}", e)))
    }

    pub async fn create_record(record: Record) -> Result<Record, ServiceError> {
        get_record_repository()
            .create(record)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to create record: {}", e)))
    }

    pub async fn create_record_tx(
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, ServiceError> {
        get_record_repository()
            .create_tx(tx, record)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to create record: {}", e)))
    }

    pub async fn update_record(record: Record) -> Result<Record, ServiceError> {
        get_record_repository()
            .update(record)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to update record: {}", e)))
    }

    pub async fn update_record_tx(
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, ServiceError> {
        get_record_repository()
            .update_tx(tx, record)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to update record: {}", e)))
    }

    pub async fn get_all_records() -> Result<Vec<Record>, ServiceError> {
        get_record_repository()
            .get_all()
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load records: {}", e)))
    }

    pub async fn get_record_by_id(record_id: i32) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get_by_id(record_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load record: {}", e)))
    }

    pub async fn get_record(
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get(zone_id, name, record_type, value, priority, match_priority)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load record: {}", e)))
    }

    pub async fn get_record_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, ServiceError> {
        get_record_repository()
            .get_tx(
                tx,
                zone_id,
                name,
                record_type,
                value,
                priority,
                match_priority,
            )
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load record: {}", e)))
    }

    pub async fn delete_record(record_id: i32) -> Result<(), ServiceError> {
        get_record_repository()
            .delete(record_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to delete record: {}", e)))
    }

    pub async fn delete_record_tx(
        tx: &mut RepositoryTx<'_>,
        record_id: i32,
    ) -> Result<(), ServiceError> {
        get_record_repository()
            .delete_tx(tx, record_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to delete record: {}", e)))
    }

    pub async fn create_zone_change(change: ZoneChange) -> Result<ZoneChange, ServiceError> {
        get_zone_change_repository()
            .create(change)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to create zone change: {}", e)))
    }

    pub async fn create_zone_change_tx(
        tx: &mut RepositoryTx<'_>,
        zone_change: ZoneChange,
    ) -> Result<ZoneChange, ServiceError> {
        get_zone_change_repository()
            .create_tx(tx, zone_change)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to create zone change: {}", e)))
    }

    pub async fn get_zone_changes_between_serials(
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, ServiceError> {
        get_zone_change_repository()
            .get_changes_between_serials(zone_id, from_serial, to_serial)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load zone changes: {}", e)))
    }

    pub async fn upsert_zone_snapshot(
        snapshot: ZoneSnapshot,
    ) -> Result<ZoneSnapshot, ServiceError> {
        get_zone_snapshot_repository()
            .upsert(snapshot)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to save snapshot: {}", e)))
    }

    pub async fn upsert_zone_snapshot_tx(
        tx: &mut RepositoryTx<'_>,
        snapshot: ZoneSnapshot,
    ) -> Result<ZoneSnapshot, ServiceError> {
        get_zone_snapshot_repository()
            .upsert_tx(tx, snapshot)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to save snapshot: {}", e)))
    }

    pub async fn create_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, ServiceError> {
        get_zone_repository()
            .create_tx(tx, zone)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to create zone: {}", e)))
    }

    pub async fn update_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, ServiceError> {
        get_zone_repository()
            .update_tx(tx, zone)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to update zone: {}", e)))
    }

    pub async fn delete_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), ServiceError> {
        get_zone_repository()
            .delete_tx(tx, zone_id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to delete zone: {}", e)))
    }

    pub async fn get_zone_snapshot_by_serial(
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneSnapshot>, ServiceError> {
        get_zone_snapshot_repository()
            .get_by_zone_id_and_serial(zone_id, serial)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load snapshot: {}", e)))
    }

    pub async fn create_api_token(token: ApiToken) -> Result<ApiToken, ServiceError> {
        get_api_token_repository()
            .create(token)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to create token: {}", e)))
    }

    pub async fn get_all_api_tokens() -> Result<Vec<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_all()
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load tokens: {}", e)))
    }

    pub async fn get_api_token_by_id(id: i32) -> Result<Option<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_by_id(id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load token: {}", e)))
    }

    pub async fn get_api_token_by_token(token: &str) -> Result<Option<ApiToken>, ServiceError> {
        get_api_token_repository()
            .get_by_token(token)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to load token: {}", e)))
    }

    pub async fn update_api_token(token: ApiToken) -> Result<ApiToken, ServiceError> {
        get_api_token_repository()
            .update(token)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to update token: {}", e)))
    }

    pub async fn delete_api_token(id: i32) -> Result<(), ServiceError> {
        get_api_token_repository()
            .delete(id)
            .await
            .map_err(|e| ServiceError::Internal(format!("failed to delete token: {}", e)))
    }
}
