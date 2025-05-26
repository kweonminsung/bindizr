use crate::database::utils::{self, parse_mysql_datetime};
use chrono::{DateTime, Utc};
use mysql::Value;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ApiToken {
    pub id: i32,

    pub token: String,

    pub created_at: DateTime<Utc>,

    pub expires_at: Option<DateTime<Utc>>,

    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    pub fn from_row(row: mysql::Row) -> Self {
        ApiToken {
            id: row.get("id").unwrap(),
            token: row.get("token").unwrap(),
            created_at: parse_mysql_datetime(&row.get("created_at").unwrap()),
            expires_at: match row.get::<Value, _>("expires_at") {
                Some(value) => Some(utils::parse_mysql_datetime(&value)),
                None => None,
            },
            last_used_at: match row.get::<Value, _>("last_used_at") {
                Some(value) => Some(utils::parse_mysql_datetime(&value)),
                None => None,
            },
        }
    }
}
