use chrono::{DateTime, Utc};
use mysql::Value;

pub fn parse_mysql_datetime(timestamp: &Value) -> DateTime<Utc> {
    match timestamp {
        Value::Bytes(bytes) => {
            let timestamp_str = String::from_utf8_lossy(bytes);
            DateTime::parse_from_rfc3339(&timestamp_str)
                .unwrap()
                .with_timezone(&Utc)
        }
        _ => Utc::now(), // Default
    }
}
