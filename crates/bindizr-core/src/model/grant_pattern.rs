//! The grammar a grant's name pattern and type list share: `*` for every
//! name or type, `@` for the apex, `*.sub` for a subtree, an exact relative
//! name, and types as a comma-separated list.

use crate::{dns::name::OwnerName, model::record::RecordType};

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

/// Check whether a grant's type filter permits the requested record type.
pub fn matches_types(types: &str, record_type: Option<&RecordType>) -> bool {
    if types == MATCH_ANY {
        return true;
    }

    match record_type {
        // A whole-name delete touches every type at the name, so a type-limited
        // grant cannot cover it.
        None => false,
        Some(record_type) => types.split(',').any(|t| t == record_type.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::matches_name;
    use crate::dns::name::OwnerName;

    /// Verify that pattern matching covers all forms.
    #[test]
    fn pattern_matching_covers_all_forms() {
        assert!(matches_name("*", &OwnerName::apex()));
        assert!(matches_name("*", &OwnerName::from_row("anything.at.all")));

        assert!(matches_name("@", &OwnerName::apex()));
        assert!(!matches_name("@", &OwnerName::from_row("www")));

        assert!(matches_name("www", &OwnerName::from_row("www")));
        assert!(matches_name("www", &OwnerName::from_row("WWW")));
        assert!(!matches_name("www", &OwnerName::from_row("sub.www")));

        assert!(matches_name("*.sub", &OwnerName::from_row("sub")));
        assert!(matches_name("*.sub", &OwnerName::from_row("a.sub")));
        assert!(matches_name("*.sub", &OwnerName::from_row("a.b.sub")));
        assert!(!matches_name("*.sub", &OwnerName::from_row("sub.other")));
        assert!(!matches_name("*.sub", &OwnerName::from_row("xsub")));
    }

    /// Verify that a subtree grant does not reach a label that merely spells it.
    #[test]
    fn a_subtree_grant_does_not_reach_a_label_that_merely_spells_it() {
        // `a\.sub` is the single label `a.sub`, not a name under `sub`.
        assert!(!matches_name("*.sub", &OwnerName::from_row(r"a\.sub")));
        assert!(matches_name("*.sub", &OwnerName::from_row(r"a\.b.sub")));
    }
}
