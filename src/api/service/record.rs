use mysql::prelude::Queryable;

use crate::{
    api::dto::CreateRecordRequest,
    database::{
        model::record::{Record, RecordType},
        DatabasePool,
    },
};

use super::common::CommonService;

#[derive(Clone)]
pub struct RecordService;

impl RecordService {
    pub fn get_records(pool: &DatabasePool, zone_id: Option<i32>) -> Vec<Record> {
        let mut conn = pool.get_connection();

        match zone_id {
            Some(id) => conn
                .exec_map(
                    "SELECT * FROM records WHERE zone_id = ?",
                    (id,),
                    |row: mysql::Row| Record::from_row(row),
                )
                .unwrap_or_else(|_| Vec::new()),
            None => conn
                .exec_map("SELECT * FROM records", (), |row: mysql::Row| {
                    Record::from_row(row)
                })
                .unwrap_or_else(|_| Vec::new()),
        }
    }

    pub fn get_record(pool: &DatabasePool, record_id: i32) -> Result<Record, String> {
        CommonService::get_record_by_id(&pool, record_id)
    }

    pub fn create_record(
        pool: &DatabasePool,
        create_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        if CommonService::get_zone_by_id(&pool, create_record_request.zone_id).is_err() {
            return Err("Zone not found".to_string());
        }

        let record_type = RecordType::from_str(&create_record_request.record_type)
            .map_err(|_| format!("Invalid record type: {}", create_record_request.record_type))?;

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop(
            "INSERT INTO records (name, record_type, value, ttl, priority, zone_id) VALUES (?, ?, ?, ?, ?, ?)",
            (
                &create_record_request.name,
                record_type.to_str(),
                &create_record_request.value,
                create_record_request.ttl,
                create_record_request.priority,
                create_record_request.zone_id,
            ),
        )
        .map_err(|e| format!("Failed to insert record: {}", e))?;

        // Get last insert id
        let last_insert_id = tx
            .last_insert_id()
            .ok_or_else(|| "Failed to get last insert id".to_string())?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        CommonService::get_record_by_id(&pool, last_insert_id as i32)
    }

    pub fn update_record(
        pool: &DatabasePool,
        record_id: i32,
        update_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        if CommonService::get_record_by_id(&pool, record_id).is_err() {
            return Err("Record not found".to_string());
        }

        if CommonService::get_zone_by_id(&pool, update_record_request.zone_id).is_err() {
            return Err("Zone not found".to_string());
        }

        let record_type = RecordType::from_str(&update_record_request.record_type)
            .map_err(|_| format!("Invalid record type: {}", update_record_request.record_type))?;

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop(
            "UPDATE records SET name = ?, record_type = ?, value = ?, ttl = ?, priority = ?, zone_id = ? WHERE id = ?",
            (
                &update_record_request.name,
                record_type.to_str(),
                &update_record_request.value,
                update_record_request.ttl,
                update_record_request.priority,
                update_record_request.zone_id,
                record_id,
            ),
        )
        .map_err(|e| format!("Failed to update record: {}", e))?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        CommonService::get_record_by_id(&pool, record_id)
    }

    pub fn delete_record(pool: &DatabasePool, record_id: i32) -> Result<(), String> {
        let mut conn = pool.get_connection();

        if CommonService::get_record_by_id(&pool, record_id).is_err() {
            return Err("Record not found".to_string());
        }

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| format!("Failed to start transaction: {}", e))?;

        tx.exec_drop("DELETE FROM records WHERE id = ?", (record_id,))
            .map_err(|e| format!("Failed to delete record: {}", e))?;

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        Ok(())
    }
}
