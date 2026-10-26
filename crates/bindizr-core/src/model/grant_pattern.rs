//! Grant patterns: `*` for all, `@` for apex, `*.sub` for a subtree, exact names,
//! and comma-separated record types.

use crate::dns::name::OwnerName;
use crate::model::record::RecordType;

/// The pattern or type list that covers everything.
pub const MATCH_ANY: &str = "*";

/// Match a relative owner name (`@`, `www`, `a.b`, ...) against a grant
/// pattern: `*` (any name), `@` (apex only), `*.sub` (sub and everything under
/// it), or an exact relative name.
pub fn matches_name(pattern: &str, name: &OwnerName) -> bool {
    if pattern == MATCH_ANY {
        return true;
    }

    // Patterns are stored in presentation form, where the apex is `@`.
    if pattern == OwnerName::APEX {
        return name.is_apex();
    }

    // Compared label by label so `xsub` does not read as inside `sub`.
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return name.is_same_or_under(&OwnerName::from_row(suffix));
    }

    *name == OwnerName::from_row(pattern)
}

/// Whether every name `inner` matches, `outer` matches too.
pub fn has_pattern_coverage(outer: &str, inner: &str) -> bool {
    if outer == MATCH_ANY {
        return true;
    }
    if inner == MATCH_ANY {
        return false;
    }

    match inner.strip_prefix("*.") {
        // Only a subtree at or above it covers a subtree.
        Some(root) => outer.strip_prefix("*.").is_some_and(|outer_root| {
            OwnerName::from_row(root).is_same_or_under(&OwnerName::from_row(outer_root))
        }),
        None if inner == OwnerName::APEX => matches_name(outer, &OwnerName::apex()),
        None => matches_name(outer, &OwnerName::from_row(inner)),
    }
}

/// Check whether a grant's type filter permits the requested record type.
pub fn matches_types(types: &str, record_type: Option<&RecordType>) -> bool {
    if types == MATCH_ANY {
        return true;
    }

    match record_type {
        // A whole-name delete touches every type at the name, so a type-limited
        // grant cannot cover it.
        None => false,
        Some(record_type) => {
            let record_type = record_type.as_str();
            types
                .split(',')
                .any(|allowed_type| allowed_type == record_type)
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::dns::name::OwnerName;

    /// Verify that pattern matching covers all forms.
    #[test]
    fn pattern_matching_covers_all_forms() {
        assert!(super::matches_name("*", &OwnerName::apex()));
        assert!(super::matches_name(
            "*",
            &OwnerName::from_row("anything.at.all")
        ));

        assert!(super::matches_name("@", &OwnerName::apex()));
        assert!(!super::matches_name("@", &OwnerName::from_row("www")));

        assert!(super::matches_name("www", &OwnerName::from_row("www")));
        assert!(super::matches_name("www", &OwnerName::from_row("WWW")));
        assert!(!super::matches_name("www", &OwnerName::from_row("sub.www")));

        assert!(super::matches_name("*.sub", &OwnerName::from_row("sub")));
        assert!(super::matches_name("*.sub", &OwnerName::from_row("a.sub")));
        assert!(super::matches_name(
            "*.sub",
            &OwnerName::from_row("a.b.sub")
        ));
        assert!(!super::matches_name(
            "*.sub",
            &OwnerName::from_row("sub.other")
        ));
        assert!(!super::matches_name("*.sub", &OwnerName::from_row("xsub")));
    }

    /// Verify that a subtree grant does not reach a label that merely spells it.
    #[test]
    fn subtree_grant_rejects_escaped_label_boundary() {
        // `a\.sub` is the single label `a.sub`, not a name under `sub`.
        assert!(!super::matches_name(
            "*.sub",
            &OwnerName::from_row(r"a\.sub")
        ));
        assert!(super::matches_name(
            "*.sub",
            &OwnerName::from_row(r"a\.b.sub")
        ));
    }

    /// Verify that a pattern covers another only when every name of the
    /// inner one matches the outer, compared by label.
    #[test]
    fn has_pattern_coverage_compares_by_label() {
        assert!(super::has_pattern_coverage("*", "*.apps"));
        assert!(super::has_pattern_coverage("*.apps", "api.apps"));
        assert!(super::has_pattern_coverage("*.apps", "*.k8s.apps"));
        assert!(super::has_pattern_coverage("*.apps", "apps"));
        assert!(super::has_pattern_coverage("api.apps", "api.apps"));
        assert!(!super::has_pattern_coverage("api.apps", "*.api.apps"));
        assert!(!super::has_pattern_coverage("*.apps", "xapps"));
        assert!(!super::has_pattern_coverage("*.apps", "*"));
        assert!(!super::has_pattern_coverage("@", "www"));
        assert!(super::has_pattern_coverage("@", "@"));
    }
}
