use crate::database::utils::{self, parse_mysql_datetime};
use chrono::{DateTime, Utc};
use mysql::Value;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: i32,

    pub token: String,

    pub description: Option<String>,

    pub created_at: DateTime<Utc>,

    pub expires_at: Option<DateTime<Utc>>,

    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    pub fn from_row(row: mysql::Row) -> Self {
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
