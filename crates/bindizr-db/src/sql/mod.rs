//! Shared SQL filter fragments rendered from core types.

mod grant;
mod sort;

use bindizr_core::dns::name::OwnerName;
use bindizr_core::model::record::NAME_LIKE_RECORD_TYPES;
use chrono::{DateTime, TimeDelta, Utc};
pub(crate) use grant::{concat_fn, concat_pipes, grant_record_match_sql};
pub use sort::{
    AccessLogSortField, AuditLogSortField, ParseSortError, RecordSortField, SortOrder,
    TransferLogSortField, ZoneSortField,
};

/// Return the latest expiry any policy's re-sign window can reach: the constant
/// a query seeks the index on. Saturates, which only makes that filter a no-op.
pub(crate) fn refresh_bound(cutoff: DateTime<Utc>, max_refresh_days: i32) -> DateTime<Utc> {
    TimeDelta::try_days(i64::from(max_refresh_days))
        .and_then(|window| cutoff.checked_add_signed(window))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// Return `count` comma-separated `?` placeholders, for an `IN` list on the
/// backends whose placeholders are positional.
pub(crate) fn placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
}

/// Return the owner name the apex is stored under, as an SQL literal.
pub(crate) fn apex_owner_sql() -> String {
    format!("'{}'", OwnerName::apex().to_stored())
}

/// Return the record types that compare case-insensitively, as an SQL `IN`
/// list.
pub(crate) fn name_like_types_sql() -> String {
    NAME_LIKE_RECORD_TYPES
        .iter()
        .map(|record_type| format!("'{}'", record_type.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Return a partial-match term, trimmed; stored names carry no trailing root
/// dot.
pub(crate) fn partial_term(value: &str) -> String {
    value.trim().trim_end_matches('.').to_string()
}

/// Wrap the [`partial_term`] for a contains-match, `None` when nothing remains.
pub(crate) fn like_pattern(value: Option<&str>) -> Option<String> {
    value
        .map(partial_term)
        .filter(|term| !term.is_empty())
        .map(|term| format!("%{}%", escape_like(&term)))
}

/// Escape the LIKE wildcards for an `ESCAPE '\\'` clause; `%`, `_`, and
/// `\` all occur in names and rdata.
fn escape_like(term: &str) -> String {
    term.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
