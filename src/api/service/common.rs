use mysql::prelude::Queryable;

use crate::database::{
    model::{record::Record, zone::Zone},
    DatabasePool,
};

#[derive(Clone)]
pub struct CommonService;

impl CommonService {
    pub fn get_zone_by_id(pool: &DatabasePool, zone_id: i32) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        conn.exec_map(
            r#"
            SELECT *
            FROM zones
            WHERE id = ?
        "#,
            (zone_id,),
            |row: mysql::Row| Zone::from_row(row),
        )
        .map_err(|e| format!("Failed to fetch zone: {}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| "Zone not found".to_string())
    }

    pub fn get_record_by_id(pool: &DatabasePool, record_id: i32) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        conn.exec_map(
            r#"
            SELECT *
            FROM records
            WHERE id = ?
        "#,
            (record_id,),
            |row: mysql::Row| Record::from_row(row),
        )
        .map_err(|e| format!("Failed to fetch record: {}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| "Record not found".to_string())
    }
}
