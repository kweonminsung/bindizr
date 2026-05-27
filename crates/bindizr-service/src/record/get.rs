use crate::{
    RepositoryTx,
    error::ServiceError,
    log_error,
    model::record::{Record, RecordType},
    repository::RepositoryService,
};

use super::RecordService;

impl RecordService {
    pub async fn list_by_zone_id(zone_id: i32) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::get_records_by_zone_id(zone_id).await
    }

    pub async fn list_by_zone_id_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Vec<Record>, ServiceError> {
        RepositoryService::get_records_by_zone_id_tx(tx, zone_id).await
    }

    pub async fn find_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: Option<i32>,
        name: &str,
        record_type: &RecordType,
        value: Option<&str>,
        priority: Option<i32>,
        match_priority: bool,
    ) -> Result<Option<Record>, ServiceError> {
        RepositoryService::get_record_tx(
            tx,
            zone_id,
            name,
            record_type,
            value,
            priority,
            match_priority,
        )
        .await
    }

    pub async fn list(zone_name: Option<String>) -> Result<Vec<Record>, ServiceError> {
        match zone_name {
            Some(name) => {
                // Check if zone exists and get zone_id
                let zone = match RepositoryService::get_zone_by_name(&name).await {
                    Ok(Some(z)) => z,
                    Ok(None) => {
                        return Err(ServiceError::BadRequest(format!(
                            "Zone with name '{}' not found",
                            name
                        )));
                    }
                    Err(e) => {
                        log_error!("Failed to fetch zone: {}", e);
                        return Err(ServiceError::Internal("Failed to fetch zone".to_string()));
                    }
                };

                // Fetch records by zone_id
                match RepositoryService::get_records_by_zone_id(zone.id).await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch records for zone {}: {}", name, e);
                        Err(ServiceError::Internal(format!(
                            "Failed to fetch records for zone {}",
                            name
                        )))
                    }
                }
            }
            None => {
                // Fetch all records
                match RepositoryService::get_all_records().await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch all records: {}", e);
                        Err(ServiceError::Internal(
                            "Failed to fetch all records".to_string(),
                        ))
                    }
                }
            }
        }
    }

    pub async fn get_by_id(record_id: i32) -> Result<Record, ServiceError> {
        match RepositoryService::get_record_by_id(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(ServiceError::NotFound(format!(
                "Record with id '{}' not found",
                record_id
            ))),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err(ServiceError::Internal("Failed to fetch record".to_string()))
            }
        }
    }
}
