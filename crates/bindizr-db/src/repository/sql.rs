//! SQL fragments and search-term normalization shared by the per-backend
//! filter queries, rendered from the core types so no backend can drift.

use bindizr_core::dns::name::OwnerName;
use chrono::{DateTime, TimeDelta, Utc};

use super::LockLevel;
use crate::model::record::NAME_LIKE_RECORD_TYPES;

/// The latest expiry any policy's re-sign window can reach: the constant a
/// query seeks the index on. Saturates, which only makes that filter a no-op.
pub(crate) fn refresh_bound(cutoff: DateTime<Utc>, max_refresh_days: i32) -> DateTime<Utc> {
    TimeDelta::try_days(i64::from(max_refresh_days))
        .and_then(|window| cutoff.checked_add_signed(window))
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// The locking clause for `lock_level`, as a suffix appended after any
/// `ORDER BY`. SQLite locks the whole database instead, so it never calls this.
pub(crate) fn lock_clause(lock_level: LockLevel) -> &'static str {
    match lock_level {
        LockLevel::Exclusive => " FOR UPDATE",
        LockLevel::Shared => " FOR SHARE",
        LockLevel::None => "",
    }
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

/// Trim a partial-match term; stored names carry no trailing root dot.
pub(crate) fn trim_partial_value(value: &str) -> String {
    value.trim().trim_end_matches('.').to_string()
}

/// Wrap the term for a contains-match, normalized like
/// [`trim_partial_value`]. The LIKE wildcards are escaped: `%` and `_`
/// are ordinary characters in rdata and `_dmarc`-style names.
pub(crate) fn like_pattern(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let escaped = value
                .trim_end_matches('.')
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{}%", escaped)
        })
}

#[cfg(test)]
mod tests {
    use super::{apex_owner_sql, name_like_types_sql};

    #[test]
    fn apex_owner_renders_as_a_quoted_sql_literal() {
        // Interpolated straight into `r.name = ...`, so the quoting is part of
        // the query's syntax.
        assert_eq!(apex_owner_sql(), "''");
    }

    #[test]
    fn name_like_types_render_as_a_quoted_sql_list() {
        // Interpolated straight into `IN (...)`, so the quoting and separator
        // are part of the query's syntax.
        assert_eq!(name_like_types_sql(), "'CNAME','NS','PTR','MX','SRV'");
    }
}
