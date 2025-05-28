use crate::database::utils;
use chrono::{DateTime, Utc};
use mysql::Value;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ZoneHistory {
    pub(crate) id: i32,

    pub(crate) log: String,

    pub(crate) created_at: DateTime<Utc>,

    pub(crate) updated_at: DateTime<Utc>,

    pub(crate) zone_id: i32,
}

impl ZoneHistory {
    pub(crate) fn from_row(row: mysql::Row) -> Self {
        ZoneHistory {
            id: row.get("id").unwrap(),
            log: row.get("log").unwrap(),
            created_at: utils::parse_mysql_datetime(&row.get::<Value, _>("created_at").unwrap()),
            updated_at: utils::parse_mysql_datetime(&row.get::<Value, _>("updated_at").unwrap()),
            zone_id: row.get("zone_id").unwrap(),
        }
    }
}
