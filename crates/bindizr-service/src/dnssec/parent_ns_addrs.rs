//! The zone's `parent_ns_addrs` setting: the parent nameservers its DS is
//! asked from, as the operator spells them.

use bindizr_core::dns::{address::is_address_target, name::has_whitespace_or_control};

use crate::error::ServiceError;

/// The width of the `zones.parent_ns_addrs` column.
const MAX_PARENT_NS_ADDRS_LEN: usize = 1024;

/// Trim a list of `host[:port]` entries into its stored form, the entries
/// joined with commas. A zone's DS can only be asked at the servers it names,
/// so an empty list is an error.
pub(crate) fn normalize_parent_ns_addrs(entries: &[String]) -> Result<String, ServiceError> {
    let entries: Vec<&str> = entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() {
        return Err(ServiceError::invalid_input(
            "give at least one parent nameserver as host[:port]",
        ));
    }
    for entry in &entries {
        if has_whitespace_or_control(entry) || !is_address_target(entry) {
            return Err(ServiceError::invalid_input(format!(
                "parent address '{}' must be host[:port] with a numeric port",
                entry
            )));
        }
    }
    let joined = entries.join(",");
    if joined.len() > MAX_PARENT_NS_ADDRS_LEN {
        return Err(ServiceError::invalid_input(format!(
            "parent nameserver list is {} characters; at most {} are stored",
            joined.len(),
            MAX_PARENT_NS_ADDRS_LEN
        )));
    }
    Ok(joined)
}

/// The entries of a stored parent nameserver list.
pub(crate) fn parent_ns_addr_entries(stored: &str) -> Vec<String> {
    stored.split(',').map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::{normalize_parent_ns_addrs, parent_ns_addr_entries};
    use crate::error::ErrorCode;

    /// Turn string literals into the owned entries the normalizer takes.
    fn entries(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    /// Verify that `normalize_parent_ns_addrs` trims entries and drops empty ones.
    #[test]
    fn normalize_parent_ns_addrs_trims_entries() {
        assert_eq!(
            normalize_parent_ns_addrs(&entries(&[
                " ns1.parent.example ",
                "",
                " ns2.parent.example:5353 "
            ]))
            .unwrap(),
            "ns1.parent.example,ns2.parent.example:5353"
        );
    }

    /// Verify that `normalize_parent_ns_addrs` rejects an empty list.
    #[test]
    fn normalize_parent_ns_addrs_rejects_an_empty_list() {
        let err = normalize_parent_ns_addrs(&entries(&[" ", ""])).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    /// Verify that `normalize_parent_ns_addrs` rejects an entry that is not an address target.
    #[test]
    fn normalize_parent_ns_addrs_rejects_an_entry_that_is_not_an_address_target() {
        let err =
            normalize_parent_ns_addrs(&entries(&["ns.parent.example:not-a-port"])).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    /// Verify that `normalize_parent_ns_addrs` rejects a list wider than the column.
    #[test]
    fn normalize_parent_ns_addrs_rejects_a_list_wider_than_the_column() {
        let entry = format!("{}.parent.example", "n".repeat(60));
        let err = normalize_parent_ns_addrs(&vec![entry; 20]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    /// Verify that the stored form splits back into the entries it was built from.
    #[test]
    fn parent_ns_addr_entries_splits_the_stored_form() {
        assert_eq!(
            parent_ns_addr_entries("ns1.parent.example,ns2.parent.example:5353"),
            entries(&["ns1.parent.example", "ns2.parent.example:5353"])
        );
    }
}
