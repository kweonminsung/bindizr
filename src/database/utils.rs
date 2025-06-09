use chrono::{DateTime, Utc};
use mysql::Value;

pub(crate) fn parse_mysql_datetime(timestamp: &Value) -> DateTime<Utc> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use mysql::Value;

    #[test]
    fn test_parse_mysql_datetime() {
        let timestamp = Value::Bytes(b"2023-10-01T12:00:00Z".to_vec());
        let parsed = parse_mysql_datetime(&timestamp);
        assert_eq!(parsed.to_rfc3339(), "2023-10-01T12:00:00+00:00");
    }

    #[test]
    fn test_parse_invalid_mysql_datetime() {
        let timestamp = Value::Int(0);
        let parsed = parse_mysql_datetime(&timestamp);
        assert!(parsed < Utc::now());
    }
}
