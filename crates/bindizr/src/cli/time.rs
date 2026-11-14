//! Time flags: how a command line names a moment.

use chrono::{DateTime, Duration, NaiveDate, NaiveTime, Utc};
use thiserror::Error;

/// A time flag in none of the forms the command reads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{value}' is not a span ago (7d, 12h, 30m), a date (2026-10-01), or an RFC 3339 time")]
pub(crate) struct ParseTimeError {
    value: String,
}

/// Parse a time flag into UTC: a span ago (`7d`, `12h`, `30m`), a date read
/// as midnight UTC, or an RFC 3339 timestamp.
pub(crate) fn parse_time(value: &str) -> Result<DateTime<Utc>, ParseTimeError> {
    let value = value.trim();
    let invalid = || ParseTimeError {
        value: value.to_string(),
    };

    if let Some(span) = parse_span(value) {
        return Utc::now().checked_sub_signed(span).ok_or_else(invalid);
    }
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return Ok(date.and_time(NaiveTime::MIN).and_utc());
    }

    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| invalid())
}

/// Read `<n>m`, `<n>h`, or `<n>d` as a span; anything else is not one.
fn parse_span(value: &str) -> Option<Duration> {
    let (digits, unit) = value.split_at_checked(value.len().checked_sub(1)?)?;
    let count = digits.parse::<u32>().ok().map(i64::from)?;

    match unit {
        "m" => Duration::try_minutes(count),
        "h" => Duration::try_hours(count),
        "d" => Duration::try_days(count),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    /// Verify that `parse_time` reads a span ago, a UTC date, and an RFC 3339 time.
    #[test]
    fn parse_time_reads_span_date_and_rfc3339() {
        for (value, span) in [
            ("7d", Duration::days(7)),
            ("12h", Duration::hours(12)),
            ("30m", Duration::minutes(30)),
        ] {
            let before = Utc::now();
            let parsed = parse_time(value).unwrap();
            let after = Utc::now();

            assert!(
                parsed >= before - span && parsed <= after - span,
                "{value}: {parsed}"
            );
        }

        let midnight = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();

        assert_eq!(parse_time("2026-10-01").unwrap(), midnight);
        assert_eq!(parse_time(" 2026-10-01 ").unwrap(), midnight);
        assert_eq!(parse_time("2026-10-01T09:00:00+09:00").unwrap(), midnight);
        assert_eq!(parse_time("2026-10-01T00:00:00Z").unwrap(), midnight);
    }

    /// Verify that `parse_time` refuses what is none of the three forms.
    #[test]
    fn parse_time_rejects_other_forms() {
        for value in [
            "",
            "d",
            "7x",
            "7",
            "-7d",
            "7.5d",
            "2026-13-01",
            "yesterday",
            "2026-10-01T25:00:00Z",
        ] {
            assert!(parse_time(value).is_err(), "{value:?}");
        }
    }
}
