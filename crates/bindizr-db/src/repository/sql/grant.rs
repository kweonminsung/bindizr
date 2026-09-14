//! The narrowing a token grant puts on the records a listing may return,
//! rendered once for every backend's filter queries.

use super::apex_owner_sql;

/// String concatenation for the backends that spell it `||`.
pub(crate) fn concat_pipes(parts: &[&str]) -> String {
    parts.join(" || ")
}

/// String concatenation for MySQL, where `||` is logical OR.
pub(crate) fn concat_fn(parts: &[&str]) -> String {
    format!("CONCAT({})", parts.join(", "))
}

/// The `LIKE` escape character. A stored name carries backslashes as data
/// (RFC 1035, Section 5.1), which the default escape would eat — and `#` needs
/// no escaping in a string literal, so one spelling works on all three.
const LIKE_ESCAPE: char = '#';

/// Escape a stored name for use as a `LIKE` pattern: the escape character
/// first, so the ones it adds are not escaped again.
fn escaped_for_like(expression: &str) -> String {
    let mut escaped = expression.to_string();
    for character in [LIKE_ESCAPE, '%', '_'] {
        escaped = format!("REPLACE({escaped}, '{character}', '{LIKE_ESCAPE}{character}')");
    }
    escaped
}

/// A condition on the `token_grants` row `p` and the record `alias`. Pass the
/// record's type column, or `None` for the derived DNSSEC plane, which carries
/// no type of the grant's vocabulary.
///
/// SQL cannot read a stored name as the labels of RFC 1035, Section 5.1, so a
/// subtree pattern matches by text and over-approximates — `a\.sub` is one
/// label but passes as if it were under `sub`. That never drops a row the
/// caller may see, and the service decides again on labels.
pub(crate) fn grant_record_match_sql(
    alias: &str,
    record_type_column: Option<&str>,
    concat: impl Fn(&[&str]) -> String,
) -> String {
    let apex = apex_owner_sql();
    let suffix = "SUBSTR(p.record_name_pattern, 3)";
    let under = concat(&["'%.'", &escaped_for_like(suffix)]);
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
    format!("{name} AND {types}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a grant pattern narrows by name and type.
    #[test]
    fn a_grant_pattern_narrows_by_name_and_type() {
        let sql = grant_record_match_sql("r", Some("record_type"), concat_pipes);

        assert!(sql.contains("p.record_name_pattern = '*'"));
        assert!(sql.contains("r.name = ''"));
        // The backslash a stored name carries is data, not a LIKE escape.
        assert!(sql.contains("ESCAPE '#'"));
        assert!(sql.contains("REPLACE(REPLACE(REPLACE(SUBSTR(p.record_name_pattern, 3)"));
        assert!(sql.contains("',' || p.record_types || ',' LIKE '%,' || r.record_type || ',%'"));
    }

    /// Verify that the derived plane reaches only a grant that limits no type.
    #[test]
    fn the_derived_plane_reaches_only_a_grant_that_limits_no_type() {
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
