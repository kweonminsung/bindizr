//! The zone's `parent_ns_addrs` setting: the parent nameservers its DS is
//! asked from, as the operator spells them.

use bindizr_core::dns::{address::is_address_target, name::has_whitespace_or_control};

use crate::error::ServiceError;

/// The width of the `zones.parent_ns_addrs` column.
const MAX_PARENT_NS_ADDRS_LEN: usize = 1024;

/// Trim a comma-separated `host[:port]` list into its stored form. A zone's
/// DS can only be asked at the servers it names, so an empty list is an
/// error.
pub(crate) fn normalize_parent_ns_addrs(raw: &str) -> Result<String, ServiceError> {
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
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

#[cfg(test)]
mod tests {
    use super::normalize_parent_ns_addrs;
    use crate::error::ErrorCode;

    #[test]
    fn normalize_parent_ns_addrs_trims_entries() {
        assert_eq!(
            normalize_parent_ns_addrs(" ns1.parent.example , ns2.parent.example:5353 ").unwrap(),
            "ns1.parent.example,ns2.parent.example:5353"
        );
    }

    #[test]
    fn normalize_parent_ns_addrs_rejects_an_empty_list() {
        let err = normalize_parent_ns_addrs(" , ").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn normalize_parent_ns_addrs_rejects_an_entry_that_is_not_an_address_target() {
        let err = normalize_parent_ns_addrs("ns.parent.example:not-a-port").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn normalize_parent_ns_addrs_rejects_a_list_wider_than_the_column() {
        let entry = format!("{}.parent.example", "n".repeat(60));
        let raw = vec![entry.as_str(); 20].join(",");
        let err = normalize_parent_ns_addrs(&raw).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
