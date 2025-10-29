use crate::{
    api::dto::CreateRecordRequest,
    database::{
        get_record_history_repository, get_record_repository, get_zone_repository,
        model::{
            record::{Record, RecordType},
            record_history::RecordHistory,
        },
    },
    log_error,
};
use chrono::Utc;

#[derive(Clone)]
pub struct RecordService;

impl RecordService {
    pub async fn get_records(zone_id: Option<i32>) -> Result<Vec<Record>, String> {
        let zone_repository = get_zone_repository();
        let record_repository = get_record_repository();

        match zone_id {
            Some(id) => {
                // Check if zone exists
                match zone_repository.get_by_id(id).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err("Zone not found".to_string());
                    }
                    Err(e) => {
                        log_error!("Failed to fetch zone: {}", e);
                        return Err("Failed to fetch zone".to_string());
                    }
                }

                // Fetch records by zone_id
                match record_repository.get_by_zone_id(id).await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch records for zone {}: {}", id, e);
                        Err(format!("Failed to fetch records for zone {}", id))
                    }
                }
            }
            None => {
                // Fetch all records
                match record_repository.get_all().await {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch all records: {}", e);
                        Err("Failed to fetch all records".to_string())
                    }
                }
            }
        }
    }

    pub async fn get_record(record_id: i32) -> Result<Record, String> {
        let record_repository = get_record_repository();

        match record_repository.get_by_id(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(format!("Record with id {} not found", record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err("Failed to fetch record".to_string())
            }
        }
    }

    pub async fn create_record(
        create_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let zone_repository = get_zone_repository();
        let record_repository = get_record_repository();
        let record_history_repository = get_record_history_repository();

        // Validate record type
        let record_type = RecordType::from_str(&create_record_request.record_type)
            .map_err(|_| format!("Invalid record type: {}", create_record_request.record_type))?;

        // SOA validation
        if record_type == RecordType::SOA {
            log_error!("Cannot create SOA record manually");
            return Err("Cannot create SOA record manually".to_string());
        }

        // Check if zone exists and fetch existing records in the zone for CNAME validation
        let zone = match zone_repository
            .get_by_id(create_record_request.zone_id)
            .await
        {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                return Err(format!(
                    "Zone with id {} not found",
                    create_record_request.zone_id
                ));
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err("Failed to create record".to_string());
            }
        };

        // Prevent manual creation of records related to primary_ns
        if (record_type == RecordType::NS && create_record_request.name == "@")
            || (record_type == RecordType::A && create_record_request.name == zone.primary_ns)
            || (record_type == RecordType::AAAA && create_record_request.name == zone.primary_ns)
        {
            return Err(
                "Cannot manually create records that are automatically generated for the primary NS"
                    .to_string(),
            );
        }

        // CNAME validation - fetch records from the same zone for efficient validation
        let existing_records_in_zone = match record_repository
            .get_by_zone_id(create_record_request.zone_id)
            .await
        {
            Ok(records) => records,
            Err(e) => {
                log_error!("Failed to check existing records: {}", e);
                return Err("Failed to create record".to_string());
            }
        };

        let existing_records_with_name: Vec<_> = existing_records_in_zone
            .iter()
            .filter(|r| r.name == create_record_request.name)
            .collect();

        if !existing_records_with_name.is_empty() {
            if record_type == RecordType::CNAME {
                return Err(format!(
                    "A record with name '{}' already exists in this zone, so CNAME cannot be used",
                    create_record_request.name
                ));
            }
            if existing_records_with_name
                .iter()
                .any(|r| r.record_type == RecordType::CNAME)
            {
                return Err(format!(
                    "A CNAME record with name '{}' already exists in this zone",
                    create_record_request.name
                ));
            }
        }

        // Create record
        let created_record = record_repository
            .create(Record {
                id: 0, // Will be set by the database
                name: create_record_request.name.clone(),
                record_type,
                value: create_record_request.value.clone(),
                ttl: create_record_request.ttl,
                priority: create_record_request.priority,
                zone_id: create_record_request.zone_id,
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create record: {}", e);
                "Failed to create record".to_string()
            })?;

        // Create record history
        record_history_repository
            .create(RecordHistory {
                id: 0, // Will be set by the database
                record_id: created_record.id,
                log: format!(
                    "[{}] Record created: id={}, zone_id={}, name={}, type={}, value={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    created_record.id,
                    create_record_request.zone_id,
                    create_record_request.name,
                    create_record_request.record_type,
                    create_record_request.value,
                ),
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create record history: {}", e);
                "Failed to create record history".to_string()
            })?;

        Ok(created_record)
    }

    pub async fn update_record(
        record_id: i32,
        update_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let zone_repository = get_zone_repository();
        let record_repository = get_record_repository();
        let record_history_repository = get_record_history_repository();

        // Check if record exists
        match record_repository.get_by_id(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(format!("Record with id {} not found", record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err("Failed to fetch record".to_string())
            }
        }?;

        // Check if zone exists
        let zone = match zone_repository
            .get_by_id(update_record_request.zone_id)
            .await
        {
            Ok(Some(zone)) => zone,
            Ok(None) => {
                return Err("Zone not found".to_string());
            }
            Err(e) => {
                log_error!("Failed to fetch zone: {}", e);
                return Err("Failed to fetch zone".to_string());
            }
        };

        // Validate record type
        let record_type = RecordType::from_str(&update_record_request.record_type)
            .map_err(|_| format!("Invalid record type: {}", update_record_request.record_type))?;

        // SOA validation
        if record_type == RecordType::SOA {
            log_error!("Cannot update to SOA record type");
            return Err("Cannot update to SOA record type".to_string());
        }

        // Prevent manual update of records related to primary_ns
        if (record_type == RecordType::NS && update_record_request.name == "@")
            || (record_type == RecordType::A && update_record_request.name == zone.primary_ns)
            || (record_type == RecordType::AAAA && update_record_request.name == zone.primary_ns)
        {
            return Err(
                "Cannot manually update records that are automatically generated for the primary NS"
                    .to_string(),
            );
        }

        // CNAME validation
        let existing_records = match record_repository
            .get_by_name(&update_record_request.name)
            .await
        {
            Ok(records) => records,
            Err(e) => {
                log_error!("Failed to check existing record: {}", e);
                return Err("Failed to update record".to_string());
            }
        };

        let other_records_in_zone: Vec<_> = existing_records
            .into_iter()
            .filter(|r| r.id != record_id && r.zone_id == update_record_request.zone_id)
            .collect();

        if !other_records_in_zone.is_empty() {
            if record_type == RecordType::CNAME {
                return Err(format!(
                    "A record with name '{}' already exists in this zone, so CNAME cannot be used",
                    update_record_request.name
                ));
            }
            if other_records_in_zone
                .iter()
                .any(|r| r.record_type == RecordType::CNAME)
            {
                return Err(format!(
                    "A CNAME record with name '{}' already exists in this zone",
                    update_record_request.name
                ));
            }
        }

        // Update record
        let updated_record = record_repository
            .update(Record {
                id: record_id,
                name: update_record_request.name.clone(),
                record_type,
                value: update_record_request.value.clone(),
                ttl: update_record_request.ttl,
                priority: update_record_request.priority,
                zone_id: update_record_request.zone_id,
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to update record: {}", e);
                "Failed to update record".to_string()
            })?;

        // Create record history
        record_history_repository
            .create(RecordHistory {
                id: 0, // Will be set by the database
                record_id: updated_record.id,
                log: format!(
                    "[{}] Record updated: id={}, zone_id={}, name={}, type={}, value={}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                    updated_record.id,
                    update_record_request.zone_id,
                    update_record_request.name,
                    update_record_request.record_type,
                    update_record_request.value,
                ),
                created_at: Utc::now(), // Will be set by the database
            })
            .await
            .map_err(|e| {
                log_error!("Failed to create record history: {}", e);
                "Failed to create record history".to_string()
            })?;

        Ok(updated_record)
    }

    pub async fn delete_record(record_id: i32) -> Result<(), String> {
        let record_repository = get_record_repository();
        // let record_history_repository = get_record_history_repository();

        // Check if record exists
        let existing_record = match record_repository.get_by_id(record_id).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(format!("Record with id {} not found", record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                Err("Failed to fetch record".to_string())
            }
        }?;

        // Prevent deletion of SOA records
        if existing_record.record_type == RecordType::SOA {
            log_error!("Cannot delete SOA record");
            return Err("Cannot delete SOA record".to_string());
        }

        // Delete record
        record_repository.delete(record_id).await.map_err(|e| {
            log_error!("Failed to delete record: {}", e);
            "Failed to delete record".to_string()
        })?;

        // Create record history
        // record_history_repository
        //     .create(RecordHistory {
        //         id: 0, // Will be set by the database
        //         record_id,
        //         log: format!(
        //             "[{}] Record deleted: id={}",
        //             Utc::now().format("%Y-%m-%d %H:%M:%S"),
        //             record_id,
        //         ),
        //         created_at: Utc::now(), // Will be set by the database
        //     })
        //     .await
        //     .map_err(|e| {
        //         log_error!("Failed to create record history: {}", e);
        //         "Failed to create record history".to_string()
        //     })?;

        Ok(())
    }
}
