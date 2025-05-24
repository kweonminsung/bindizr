use crate::database::{
    model::{record::Record, zone::Zone},
    DatabasePool,
};
use mysql::prelude::Queryable;

#[derive(Clone)]
pub struct CommonService;

impl CommonService {
    pub fn get_zone_by_id(pool: &DatabasePool, zone_id: i32) -> Result<Zone, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
            SELECT *
            FROM zones
            WHERE id = ?
        "#,
            (zone_id,),
            |row: mysql::Row| Zone::from_row(row),
        ) {
            Ok(zones) => zones,
            Err(e) => {
                eprintln!("Failed to fetch zone: {}", e);
                return Err("Failed to fetch zone".to_string());
            }
        };

        res.into_iter()
            .next()
            .ok_or_else(|| "Zone not found".to_string())
    }

    pub fn get_record_by_id(pool: &DatabasePool, record_id: i32) -> Result<Record, String> {
        let mut conn = pool.get_connection();

        let res = match conn.exec_map(
            r#"
            SELECT *
            FROM records
            WHERE id = ?
        "#,
            (record_id,),
            |row: mysql::Row| Record::from_row(row),
        ) {
            Ok(records) => records,
            Err(e) => {
                eprintln!("Failed to fetch record: {}", e);
                return Err("Failed to fetch record".to_string());
            }
        };

        res.into_iter()
            .next()
            .ok_or_else(|| "Record not found".to_string())
    }
}
