//! Grant patterns: `*` for all, `@` for apex, `*.sub` for a subtree, exact names,
//! and comma-separated record types.

use thiserror::Error;

use crate::dns::name::{OwnerName, ParseNameError};
use crate::model::record::RecordType;

/// The pattern or type list that covers everything.
pub const MATCH_ANY: &str = "*";

/// Why the name part of a grant pattern is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParsePatternOwnerError {
    #[error("{0}")]
    Name(#[from] ParseNameError),
    #[error("contains a wildcard octet")]
    Wildcard,
}

/// Return whether a relative owner name (`@`, `www`, `a.b`, ...) matches a grant
/// pattern: `*` (any name), `@` (apex only), `*.sub` (sub and everything under
/// it), or an exact relative name.
pub fn matches_name(pattern: &str, owner: &OwnerName) -> bool {
    if pattern == MATCH_ANY {
        return true;
    }

    // Patterns are stored in presentation form, where the apex is `@`.
    if pattern == OwnerName::APEX {
        return owner.is_apex();
    }

    // Compared label by label so `xsub` does not read as inside `sub`.
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return parse_pattern_owner(suffix).is_ok_and(|root| owner.is_same_or_under(&root));
    }

    parse_pattern_owner(pattern).is_ok_and(|exact| *owner == exact)
}

/// Parse a stored exact name or an extracted subtree root. The apex has its
/// own explicit pattern and an invalid stored pattern grants no names.
pub fn parse_pattern_owner(value: &str) -> Result<OwnerName, ParsePatternOwnerError> {
    let owner = OwnerName::parse_relative(value)?;

    // The wildcard is pattern syntax. Escaping its octet does not make it
    // usable as a literal because canonical rendering would lose that escape.
    if owner.labels().iter().any(|label| label.contains(&b'*')) {
        return Err(ParsePatternOwnerError::Wildcard);
    }

    Ok(owner)
}

/// Return whether every name `inner` matches, `outer` matches too.
pub fn has_pattern_coverage(outer: &str, inner: &str) -> bool {
    if inner == MATCH_ANY {
        return outer == MATCH_ANY;
    }

    match inner.strip_prefix("*.") {
        // A subtree needs an unrestricted grant or another subtree at or above it.
        Some(root) => parse_pattern_owner(root).is_ok_and(|inner| {
            outer == MATCH_ANY
                || outer
                    .strip_prefix("*.")
                    .and_then(|name| parse_pattern_owner(name).ok())
                    .is_some_and(|outer| inner.is_same_or_under(&outer))
        }),
        None if inner == OwnerName::APEX => matches_name(outer, &OwnerName::apex()),
        None => parse_pattern_owner(inner).is_ok_and(|inner| matches_name(outer, &inner)),
    }
}

/// Return whether a grant's type filter permits the requested record type.
pub fn matches_types(types: &str, record_type: Option<RecordType>) -> bool {
    if types == MATCH_ANY {
        return true;
    }

    match record_type {
        Some(record_type) => {
            let record_type = record_type.as_str();
            types
                .split(',')
                .any(|allowed_type| allowed_type == record_type)
        }
        // A whole-name delete touches every type at the name, so a type-limited
        // grant cannot cover it.
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that invalid stored patterns cannot match or contribute name coverage.
    #[test]
    fn invalid_stored_grant_does_not_cover_names() {
        for (pattern, name) in [
            ("*.", "www.sub"),
            (r"www\", "www"),
            ("sub.", "sub"),
            ("*.sub.", "www.sub"),
            (r"a\042b", "a*b"),
            (r"*.\042", "www.*"),
        ] {
            let owner = OwnerName::from_row(name).unwrap();
            assert!(!matches_name(pattern, &owner), "{pattern:?}");
            assert!(!has_pattern_coverage(pattern, name), "{pattern:?}");
            assert!(!has_pattern_coverage(MATCH_ANY, pattern), "{pattern:?}");
        }
    }

    /// Verify that pattern matching covers all forms.
    #[test]
    fn pattern_matching_covers_all_forms() {
        assert!(matches_name("*", &OwnerName::apex()));
        assert!(matches_name(
            "*",
            &OwnerName::from_row("anything.at.all").unwrap()
        ));

        assert!(matches_name("@", &OwnerName::apex()));
        assert!(!matches_name("@", &OwnerName::from_row("www").unwrap()));

        assert!(matches_name("www", &OwnerName::from_row("www").unwrap()));
        assert!(matches_name("www", &OwnerName::from_row("WWW").unwrap()));
        assert!(!matches_name(
            "www",
            &OwnerName::from_row("sub.www").unwrap()
        ));

        assert!(matches_name("*.sub", &OwnerName::from_row("sub").unwrap()));
        assert!(matches_name(
            "*.sub",
            &OwnerName::from_row("a.sub").unwrap()
        ));
        assert!(matches_name(
            "*.sub",
            &OwnerName::from_row("a.b.sub").unwrap()
        ));
        assert!(!matches_name(
            "*.sub",
            &OwnerName::from_row("sub.other").unwrap()
        ));
        assert!(!matches_name(
            "*.sub",
            &OwnerName::from_row("xsub").unwrap()
        ));
    }

    /// Verify that a subtree grant does not reach a label that merely spells it.
    #[test]
    fn subtree_grant_rejects_escaped_label_boundary() {
        // `a\.sub` is the single label `a.sub`, not a name under `sub`.
        assert!(!matches_name(
            "*.sub",
            &OwnerName::from_row(r"a\.sub").unwrap()
        ));
        assert!(matches_name(
            "*.sub",
            &OwnerName::from_row(r"a\.b.sub").unwrap()
        ));
    }

    /// Verify that a pattern covers another only when every name of the
    /// inner one matches the outer, compared by label.
    #[test]
    fn has_pattern_coverage_compares_by_label() {
        assert!(has_pattern_coverage("*", "*.apps"));
        assert!(has_pattern_coverage("*.apps", "api.apps"));
        assert!(has_pattern_coverage("*.apps", "*.k8s.apps"));
        assert!(has_pattern_coverage("*.apps", "apps"));
        assert!(has_pattern_coverage("api.apps", "api.apps"));
        assert!(!has_pattern_coverage("api.apps", "*.api.apps"));
        assert!(!has_pattern_coverage("*.apps", "xapps"));
        assert!(!has_pattern_coverage("*.apps", "*"));
        assert!(!has_pattern_coverage("@", "www"));
        assert!(has_pattern_coverage("@", "@"));
    }
}
