use super::{common::CommonService, record_history::RecordHistoryService};
use crate::{
    api::dto::CreateRecordRequest,
    database::{
        model::record::{Record, RecordType},
        DatabasePool,
    },
    log_error,
};
use chrono::Utc;
use mysql::prelude::Queryable;

#[derive(Clone)]
pub(crate) struct RecordService;

impl RecordService {
    fn get_record_by_name(pool: &DatabasePool, record_name: &str) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
                SELECT *
                FROM records
                WHERE name = ?
            "#,
            (record_name,),
            |row: mysql::Row| Record::from_row(row),
        ) {
            Ok(record) => record,
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err("Failed to fetch record".to_string());
            }
        };

        res.into_iter()
            .next()
            .ok_or_else(|| "Record not found".to_string())
    }

    pub(crate) fn get_records(
        pool: &DatabasePool,
        zone_id: Option<i32>,
    ) -> Result<Vec<Record>, String> {
        let mut conn = pool.get_connection();

        match zone_id {
            Some(id) => {
                // Check if zone exists
                CommonService::get_zone_by_id(pool, id)?;

                match conn.exec_map(
                    r#"
                        SELECT *
                        FROM records
                        WHERE zone_id = ?
                    "#,
                    (id,),
                    |row: mysql::Row| Record::from_row(row),
                ) {
                    Ok(records) => Ok(records),
                    Err(e) => {
                        log_error!("Failed to fetch records: {}", e);
                        Err("Failed to fetch records".to_string())
                    }
                }
            }
            None => match conn.exec_map(
                r#"
                    SELECT *
                    FROM records
                "#,
                (),
                |row: mysql::Row| Record::from_row(row),
            ) {
                Ok(records) => Ok(records),
                Err(e) => {
                    log_error!("Failed to fetch records: {}", e);
                    Err("Failed to fetch records".to_string())
                }
            },
        }
    }

    pub(crate) fn get_record(pool: &DatabasePool, record_id: i32) -> Result<Record, String> {
        CommonService::get_record_by_id(pool, record_id)
    }

    pub(crate) fn create_record(
        pool: &DatabasePool,
        create_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        // Check if record already exists
        if Self::get_record_by_name(pool, &create_record_request.name).is_ok() {
            return Err(format!(
                "Record {} already exists",
                create_record_request.name
            ));
        }

        // Check if zone exists
        CommonService::get_zone_by_id(pool, create_record_request.zone_id)?;

        // Validate record type
        let record_type = RecordType::from_str(&create_record_request.record_type)
            .map_err(|_| format!("Invalid record type: {}", create_record_request.record_type))?;

        let mut tx = match conn.start_transaction(mysql::TxOpts::default()) {
            Ok(tx) => tx,
            Err(err) => {
                log_error!("Failed to start transaction: {}", err);
                return Err("Failed to create record".to_string());
            }
        };

        match tx.exec_drop(
            "INSERT INTO records (name, record_type, value, ttl, priority, zone_id) VALUES (?, ?, ?, ?, ?, ?)",
            (
                &create_record_request.name,
                record_type.to_str(),
                &create_record_request.value,
                create_record_request.ttl,
                create_record_request.priority,
                create_record_request.zone_id,
            ),
        ) {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to insert record: {}", e);
                return Err("Failed to create record".to_string());
            }
        };

        // Get last insert id
        let last_insert_id = match tx.last_insert_id() {
            Some(id) => id,
            None => {
                log_error!("Failed to get last insert id");
                return Err("Failed to create record".to_string());
            }
        };

        // Create record history
        RecordHistoryService::create_record_history(
            &mut tx,
            last_insert_id as i32,
            &format!(
                "[{}] Record created: id={}, zone_id={}, name={}, type={}, value={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                last_insert_id,
                create_record_request.zone_id,
                create_record_request.name,
                create_record_request.record_type,
                create_record_request.value,
            ),
        )?;

        match tx.commit() {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to commit transaction: {}", e);
                return Err("Failed to create record history".to_string());
            }
        };

        CommonService::get_record_by_id(pool, last_insert_id as i32)
    }

    pub(crate) fn update_record(
        pool: &DatabasePool,
        record_id: i32,
        update_record_request: &CreateRecordRequest,
    ) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        // Check if record exists
        CommonService::get_record_by_id(pool, record_id)?;

        // Check if zone exists
        CommonService::get_zone_by_id(pool, update_record_request.zone_id)?;

        let record_type = RecordType::from_str(&update_record_request.record_type)
            .map_err(|_| format!("Invalid record type: {}", update_record_request.record_type))?;

        let mut tx = match conn.start_transaction(mysql::TxOpts::default()) {
            Ok(tx) => tx,
            Err(err) => {
                log_error!("Failed to start transaction: {}", err);
                return Err("Failed to update record".to_string());
            }
        };

        match tx.exec_drop(
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
        ) {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to update record: {}", e);
                return Err("Failed to update record".to_string());
            }
        };

        // Create record history
        RecordHistoryService::create_record_history(
            &mut tx,
            record_id,
            &format!(
                "[{}] Record updated: id={}, zone_id={}, name={}, type={}, value={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                record_id,
                update_record_request.zone_id,
                update_record_request.name,
                update_record_request.record_type,
                update_record_request.value,
            ),
        )?;

        match tx.commit() {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to commit transaction: {}", e);
                return Err("Failed to update record".to_string());
            }
        };

        CommonService::get_record_by_id(pool, record_id)
    }

    pub(crate) fn delete_record(pool: &DatabasePool, record_id: i32) -> Result<(), String> {
        let mut conn = pool.get_connection();

        // Check if record exists
        CommonService::get_record_by_id(pool, record_id)?;

        let mut tx = match conn.start_transaction(mysql::TxOpts::default()) {
            Ok(tx) => tx,
            Err(err) => {
                log_error!("Failed to start transaction: {}", err);
                return Err("Failed to delete record".to_string());
            }
        };

        match tx.exec_drop("DELETE FROM records WHERE id = ?", (record_id,)) {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to delete record: {}", e);
                return Err("Failed to delete record".to_string());
            }
        };

        // Create record history
        RecordHistoryService::create_record_history(
            &mut tx,
            record_id,
            &format!(
                "[{}] Record deleted: id={}",
                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                record_id,
            ),
        )?;

        match tx.commit() {
            Ok(_) => {}
            Err(e) => {
                log_error!("Failed to commit transaction: {}", e);
                return Err("Failed to delete record".to_string());
            }
        };

        Ok(())
    }
}
