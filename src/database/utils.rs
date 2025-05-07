use chrono::{DateTime, Utc};
use std::str::FromStr;

pub fn parse_mysql_timestamp(timestamp: &str) -> DateTime<Utc> {
    DateTime::from_str(&(timestamp.to_string() + "Z")).unwrap()
}
