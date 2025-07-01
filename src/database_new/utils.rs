use chrono::{DateTime, Utc};

pub fn datetime_to_string(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn string_to_datetime(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    #[test]
    fn test_datetime_to_string() {
        let dt = DateTime::parse_from_rfc3339("2023-10-01T12:00:00Z").unwrap();
        let formatted = datetime_to_string(dt.with_timezone(&Utc));

        assert_eq!(formatted, "2023-10-01 12:00:00");
    }

    #[test]
    fn test_string_to_datetime() {
        let dt_str = "2023-10-01 12:00:00";

        let parsed = string_to_datetime(dt_str);
        assert!(parsed.is_ok());

        let dt = parsed.unwrap();

        assert_eq!(dt.year(), 2023);
        assert_eq!(dt.month(), 10);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 12);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }
}
