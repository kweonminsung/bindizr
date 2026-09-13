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

/// String concatenation for the backends that spell it `||`.
pub(crate) fn concat_pipes(parts: &[&str]) -> String {
    parts.join(" || ")
}

/// String concatenation for MySQL, where `||` is logical OR.
pub(crate) fn concat_fn(parts: &[&str]) -> String {
    format!("CONCAT({})", parts.join(", "))
}

/// The narrowing a token grant puts on the records it may read, as a
/// condition on the `token_grants` row `p` and the record `alias`. Pass the
/// record's type column, or `None` for the derived DNSSEC plane, which
/// carries no type of the grant's vocabulary.
///
/// A stored owner name carries the escapes of RFC 1035, Section 5.1, which
/// SQL cannot read as labels, so a subtree pattern matches by text and
/// over-approximates: `a\.sub` is one label but passes as if it were under
/// `sub`. That never drops a row the caller may see, and the service decides
/// again on labels.
pub(crate) fn grant_record_match_sql(
    alias: &str,
    record_type_column: Option<&str>,
    concat: impl Fn(&[&str]) -> String,
) -> String {
    let apex = apex_owner_sql();
    let suffix = "SUBSTR(p.record_name_pattern, 3)";
    let under = concat(&["'%.'", suffix]);
    let name = format!(
        "(p.record_name_pattern = '*' \
          OR (p.record_name_pattern = '@' AND {alias}.name = {apex}) \
          OR (p.record_name_pattern LIKE '*.%' \
              AND ({alias}.name = {suffix} OR {alias}.name LIKE {under})) \
          OR {alias}.name = p.record_name_pattern)"
    );
    let types = match record_type_column {
        None => "p.record_types = '*'".to_string(),
        Some(column) => {
            let haystack = concat(&["','", "p.record_types", "','"]);
            let needle = concat(&["'%,'", &format!("{alias}.{column}"), "',%'"]);
            format!("(p.record_types = '*' OR {haystack} LIKE {needle})")
        }
    };
    format!("{name} AND {types}")
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
    use super::{
        apex_owner_sql, concat_fn, concat_pipes, grant_record_match_sql, name_like_types_sql,
    };

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
        assert_eq!(
            name_like_types_sql(),
            "'CNAME','DNAME','NS','PTR','MX','SRV'"
        );
    }

    #[test]
    fn a_grant_pattern_narrows_by_name_and_type() {
        let sql = grant_record_match_sql("r", Some("record_type"), concat_pipes);

        assert!(sql.contains("p.record_name_pattern = '*'"));
        assert!(sql.contains("r.name = ''"));
        assert!(sql.contains("r.name LIKE '%.' || SUBSTR(p.record_name_pattern, 3)"));
        assert!(sql.contains("',' || p.record_types || ',' LIKE '%,' || r.record_type || ',%'"));
    }

    #[test]
    fn the_derived_plane_reaches_only_a_grant_that_limits_no_type() {
        let sql = grant_record_match_sql("d", None, concat_pipes);

        assert!(sql.ends_with("AND p.record_types = '*'"));
    }

    #[test]
    fn mysql_concatenates_with_a_function() {
        // `||` is logical OR there, so the fragment must not use it.
        let sql = grant_record_match_sql("r", Some("record_type"), concat_fn);

        assert!(sql.contains("CONCAT('%.', SUBSTR(p.record_name_pattern, 3))"));
        assert!(!sql.contains("||"));
    }
}
