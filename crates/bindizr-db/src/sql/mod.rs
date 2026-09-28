//! SQL fragments shared by the per-backend filter queries, rendered from the
//! core types so no backend can drift. The two that carry a vocabulary of
//! their own live beside this one.

mod grant;
mod sort;

use bindizr_core::dns::name::OwnerName;
use chrono::{DateTime, TimeDelta, Utc};
pub(crate) use grant::{concat_fn, concat_pipes, grant_record_match_sql};
pub use sort::{RecordSort, SortOrder, ZoneSort};

use crate::model::record::NAME_LIKE_RECORD_TYPES;

/// The latest expiry any policy's re-sign window can reach: the constant a
/// query seeks the index on. Saturates, which only makes that filter a no-op.
pub(crate) fn refresh_bound(cutoff: DateTime<Utc>, max_refresh_days: i32) -> DateTime<Utc> {
    TimeDelta::try_days(i64::from(max_refresh_days))
        .and_then(|window| cutoff.checked_add_signed(window))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// The owner name the apex is stored under, as an SQL literal.
pub(crate) fn apex_owner_sql() -> String {
    format!("'{}'", OwnerName::apex().to_stored())
}

/// The record types that compare case-insensitively, as an SQL `IN` list.
pub(crate) fn name_like_types_sql() -> String {
    NAME_LIKE_RECORD_TYPES
        .iter()
        .map(|record_type| format!("'{}'", record_type.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

/// A partial-match term, trimmed; stored names carry no trailing root dot.
pub(crate) fn partial_term(value: &str) -> String {
    value.trim().trim_end_matches('.').to_string()
}

/// Wrap the [`partial_term`] for a contains-match, `None` when nothing remains.
/// The LIKE wildcards are escaped: `%` and `_` are ordinary characters in
/// rdata and `_dmarc`-style names.
pub(crate) fn like_pattern(value: Option<&str>) -> Option<String> {
    value
        .map(partial_term)
        .filter(|term| !term.is_empty())
        .map(|term| {
            let escaped = term
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{}%", escaped)
        })
}
