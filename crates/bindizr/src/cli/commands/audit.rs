use bindizr_service::types::{AuditLogFilter, AuditLogResponse, PaginatedResponse};
use chrono::{DateTime, Duration, NaiveDate, NaiveTime, Utc};
use clap::Subcommand;
use thiserror::Error;

use crate::{
    cli::{
        error::CliError,
        output::{AuditLogRow, OutputFormat, print_page},
    },
    socket::{client, types::DaemonCommand},
};

/// Subcommands for reading the audit log.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditCommand {
    /// List the management changes, newest first: who changed what, and when
    #[command(
        alias = "ls",
        after_help = "\
Examples:
  bindizr audit list
  bindizr audit list --entity token --name external-dns
  bindizr audit list --since 7d -o json
  bindizr audit list --since 2026-10-01 --until 2026-11-01
  bindizr audit list --sort entity_name --order asc

A time is a span ago (7d, 12h, 30m), a date (2026-10-01, midnight UTC as the
AT column is), or an RFC 3339 timestamp.

A change to a token, role, grant, TSIG key, secondary or DNSSEC policy, and a
zone's deletion, is logged with the request path and the token that made it;
a socket command names no token. Changes to zone data are in the zone's
versions (`zone version list`) instead."
    )]
    List {
        /// Only changes to this kind of entity: token, role, role_grant,
        /// tsig_key, secondary, dnssec_policy, or zone
        #[arg(long, value_name = "ENTITY")]
        entity: Option<String>,
        /// Only changes to the entity of this name (a grant's is its role's)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Only changes at or after this time: a span ago (7d, 12h, 30m), a
        /// UTC date (2026-10-01), or RFC 3339
        #[arg(long, value_name = "TIME", value_parser = parse_time)]
        since: Option<DateTime<Utc>>,
        /// Only changes before this time, in the same forms
        #[arg(long, value_name = "TIME", value_parser = parse_time)]
        until: Option<DateTime<Utc>>,
        /// Sort by: created_at (default), entity, entity_name, operation
        #[arg(long, value_name = "FIELD")]
        sort: Option<String>,
        /// Sort order: desc (default) or asc
        #[arg(long, value_name = "asc|desc")]
        order: Option<String>,
        /// Maximum number of rows to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of rows to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },
}

/// A time flag in none of the forms the command reads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{value}' is not a span ago (7d, 12h, 30m), a date (2026-10-01), or an RFC 3339 time")]
struct ParseTimeError {
    value: String,
}

/// Parse a time flag into UTC: a span ago (`7d`, `12h`, `30m`), a date read
/// as midnight UTC, or an RFC 3339 timestamp.
fn parse_time(value: &str) -> Result<DateTime<Utc>, ParseTimeError> {
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

/// Handle the `audit` subcommand by dispatching to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: AuditCommand) -> Result<(), CliError> {
    match subcommand {
        AuditCommand::List {
            entity,
            name,
            since,
            until,
            sort,
            order,
            limit,
            offset,
            output,
        } => {
            let res = client::send_command::<PaginatedResponse<AuditLogResponse>>(
                DaemonCommand::ListAuditLogs(AuditLogFilter {
                    entity,
                    entity_name: name,
                    since,
                    until,
                    sort,
                    order,
                    limit,
                    offset,
                }),
            )
            .await?;
            log::debug!("Audit list result: {:?}", res);
            print_page(&res.data, output, |item| AuditLogRow::from(item))?;
        }
    }
    Ok(())
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
