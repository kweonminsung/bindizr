//! The narrowing a role grant puts on the records a listing may return,
//! rendered once for every backend's filter queries.

use bindizr_core::model::role_grant::Action;

use super::apex_owner_sql;

/// String concatenation for the backends that spell it `||`.
pub(crate) fn concat_pipes(parts: &[&str]) -> String {
    parts.join(" || ")
}

/// String concatenation for MySQL, where `||` is logical OR.
pub(crate) fn concat_fn(parts: &[&str]) -> String {
    format!("CONCAT({})", parts.join(", "))
}

/// Use `#` for LIKE escaping so stored backslashes remain data (RFC 1035, Section 5.1).
/// It needs no SQL-literal escaping on any backend.
const LIKE_ESCAPE: char = '#';

/// Escape a stored name for use as a `LIKE` pattern: the escape character
/// first, so the ones it adds are not escaped again.
fn like_escaped_sql(expression: &str) -> String {
    let mut escaped = expression.to_string();
    for character in [LIKE_ESCAPE, '%', '_'] {
        escaped = format!("REPLACE({escaped}, '{character}', '{LIKE_ESCAPE}{character}')");
    }
    escaped
}

/// Build `record:read` constraints for grant `p` and record `alias`; `None` selects derived DNSSEC.
/// Subtree matching is safe because stored in-label dots render as `\046`.
pub(crate) fn grant_record_match_sql(
    alias: &str,
    record_type_column: Option<&str>,
    concat: impl Fn(&[&str]) -> String,
) -> String {
    let actions = concat(&["','", "p.actions", "','"]);
    let read = format!("{actions} LIKE '%,{},%'", Action::RecordRead.as_str());
    let apex = apex_owner_sql();
    let suffix = "SUBSTR(p.record_name_pattern, 3)";
    let under = concat(&["'%.'", &like_escaped_sql(suffix)]);
    let name = format!(
        "(p.record_name_pattern = '*' \
          OR (p.record_name_pattern = '@' AND {alias}.name = {apex}) \
          OR (p.record_name_pattern LIKE '*.%' \
              AND ({alias}.name = {suffix} \
                   OR {alias}.name LIKE {under} ESCAPE '{LIKE_ESCAPE}')) \
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
    format!("{read} AND {name} AND {types}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a grant pattern narrows by name and type.
    #[test]
    fn grant_sql_filters_by_name_and_type() {
        let sql = grant_record_match_sql("r", Some("record_type"), concat_pipes);

        assert!(sql.starts_with("',' || p.actions || ',' LIKE '%,record:read,%' AND "));
        assert!(sql.contains("p.record_name_pattern = '*'"));
        assert!(sql.contains("r.name = ''"));
        // The backslash a stored name carries is data, not a LIKE escape.
        assert!(sql.contains("ESCAPE '#'"));
        assert!(sql.contains("REPLACE(REPLACE(REPLACE(SUBSTR(p.record_name_pattern, 3)"));
        assert!(sql.contains("',' || p.record_types || ',' LIKE '%,' || r.record_type || ',%'"));
    }

    /// Verify that the derived plane reaches only a grant that limits no type.
    #[test]
    fn grant_sql_limits_derived_records_to_unrestricted_types() {
        let sql = grant_record_match_sql("d", None, concat_pipes);

        assert!(sql.ends_with("AND p.record_types = '*'"));
    }

    /// Verify that mysql concatenates with a function.
    #[test]
    fn mysql_concatenates_with_a_function() {
        // `||` is logical OR there, so the fragment must not use it.
        let sql = grant_record_match_sql("r", Some("record_type"), concat_fn);

        assert!(sql.contains("CONCAT('%.', REPLACE("));
        assert!(!sql.contains("||"));
    }
}
