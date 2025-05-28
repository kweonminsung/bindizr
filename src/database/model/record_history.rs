use crate::database::utils;
use chrono::{DateTime, Utc};
use mysql::Value;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct RecordHistory {
    pub(crate) id: i32,

    pub(crate) log: String,

    pub(crate) created_at: DateTime<Utc>,

    pub(crate) updated_at: DateTime<Utc>,

    pub(crate) record_id: i32,
}

impl RecordHistory {
    pub(crate) fn from_row(row: mysql::Row) -> Self {
        RecordHistory {
            id: row.get("id").unwrap(),
            log: row.get("log").unwrap(),
            created_at: utils::parse_mysql_datetime(&row.get::<Value, _>("created_at").unwrap()),
            updated_at: utils::parse_mysql_datetime(&row.get::<Value, _>("updated_at").unwrap()),
            record_id: row.get("record_id").unwrap(),
        }
    }
}
