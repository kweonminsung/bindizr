use crate::database::utils;
use chrono::{DateTime, Utc};
use mysql::Value;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RecordHistory {
    pub id: i32,

    pub log: String,

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,

    pub record_id: i32,
}

impl RecordHistory {
    pub fn from_row(row: mysql::Row) -> Self {
        RecordHistory {
            id: row.get("id").unwrap(),
            log: row.get("log").unwrap(),
            created_at: utils::parse_mysql_datetime(&row.get::<Value, _>("created_at").unwrap()),
            updated_at: utils::parse_mysql_datetime(&row.get::<Value, _>("updated_at").unwrap()),
            record_id: row.get("record_id").unwrap(),
        }
    }
}
