//! The zone's `parent_ns_addrs` setting: the parent nameservers its DS is
//! asked from, as the operator spells them.

use bindizr_core::dns::{address::is_address_target, name::has_whitespace_or_control};

use crate::error::ServiceError;

/// The width of the `zones.parent_ns_addrs` column.
const MAX_PARENT_NS_ADDRS_LEN: usize = 1024;

/// Trim a comma-separated `host[:port]` list into its stored form; `None` or
/// an empty list clears the zone's parent nameservers.
pub(crate) fn normalize_parent_ns_addrs(raw: Option<&str>) -> Result<Option<String>, ServiceError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() {
        return Ok(None);
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
    Ok(Some(joined))
}

#[cfg(test)]
mod tests {
    use super::normalize_parent_ns_addrs;
    use crate::error::ErrorCode;

    #[test]
    fn normalize_parent_ns_addrs_trims_entries_and_clears_on_an_empty_list() {
        assert_eq!(
            normalize_parent_ns_addrs(Some(" ns1.parent.example , ns2.parent.example:5353 "))
                .unwrap()
                .as_deref(),
            Some("ns1.parent.example,ns2.parent.example:5353")
        );
        assert_eq!(normalize_parent_ns_addrs(Some(" , ")).unwrap(), None);
        assert_eq!(normalize_parent_ns_addrs(None).unwrap(), None);
    }

    #[test]
    fn normalize_parent_ns_addrs_rejects_an_entry_that_is_not_an_address_target() {
        let err = normalize_parent_ns_addrs(Some("ns.parent.example:not-a-port")).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn normalize_parent_ns_addrs_rejects_a_list_wider_than_the_column() {
        let entry = format!("{}.parent.example", "n".repeat(60));
        let raw = vec![entry.as_str(); 20].join(",");
        let err = normalize_parent_ns_addrs(Some(&raw)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
