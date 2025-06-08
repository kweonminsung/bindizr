use crate::database::utils::{self, parse_mysql_datetime};
use chrono::{DateTime, Utc};
use mysql::Value;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ApiToken {
    pub(crate) id: i32,

    pub(crate) token: String,

    pub(crate) description: Option<String>,

    pub(crate) created_at: DateTime<Utc>,

    pub(crate) expires_at: Option<DateTime<Utc>>,

    pub(crate) last_used_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    pub(crate) fn from_row(row: mysql::Row) -> Self {
        ApiToken {
            id: row.get("id").unwrap(),
            token: row.get("token").unwrap(),
            description: row.get("description").unwrap(),
            created_at: parse_mysql_datetime(&row.get("created_at").unwrap()),
            expires_at: row
                .get::<Value, _>("expires_at")
                .map(|value| utils::parse_mysql_datetime(&value)),
            last_used_at: row
                .get::<Value, _>("last_used_at")
                .map(|value| utils::parse_mysql_datetime(&value)),
        }
    }
}
