//! Normalize secondary identifiers and network addresses before storage.

use bindizr_core::dns::{
    address::{AddressTarget, DEFAULT_DNS_PORT, is_address_target},
    name::has_whitespace_or_control,
};

use crate::{
    error::ServiceError,
    text::{MAX_COLUMN_TEXT_LEN, normalize_identifier},
};

/// Lowercased so one name means one secondary on every backend; a plain
/// identifier, since it travels in URL paths.
pub(crate) fn normalize_secondary_name(value: &str) -> Result<String, ServiceError> {
    normalize_identifier(value, "secondary name", MAX_COLUMN_TEXT_LEN)
}

/// Canonicalize `host[:port]` with an explicit port and a lowercase host without a trailing dot
/// so `UNIQUE(address)` identifies one secondary.
pub(crate) fn normalize_secondary_address(value: &str) -> Result<AddressTarget, ServiceError> {
    let address = value.trim();

    if address.is_empty() {
        return Err(ServiceError::invalid_input(
            "secondary address must not be empty",
        ));
    }
    if has_whitespace_or_control(address) || !is_address_target(address) {
        return Err(ServiceError::invalid_input(format!(
            "secondary address '{}' must be host[:port] with a numeric port",
            address
        )));
    }
    let address = AddressTarget::parse(address, DEFAULT_DNS_PORT);
    if address.to_string().len() > MAX_COLUMN_TEXT_LEN {
        return Err(ServiceError::invalid_input(format!(
            "secondary address must be {} characters or fewer",
            MAX_COLUMN_TEXT_LEN
        )));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    /// Verify that `normalize_secondary_name` lowercases and trims.
    #[test]
    fn normalize_secondary_name_lowercases_and_trims() {
        assert_eq!(
            normalize_secondary_name("  NS2.Example ").unwrap(),
            "ns2.example"
        );
    }

    /// Verify that `normalize_secondary_name` rejects a name that is not a plain identifier.
    #[test]
    fn normalize_secondary_name_rejects_a_name_that_is_not_a_plain_identifier() {
        for name in ["", "ns 2", "ns2/eu", &"n".repeat(256)] {
            let err = normalize_secondary_name(name).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{name:?}");
        }
    }

    /// Verify that `normalize_secondary_address` spells the port out and lowercases a hostname.
    #[test]
    fn normalize_secondary_address_spells_the_port_out_and_lowercases_a_hostname() {
        assert_eq!(
            normalize_secondary_address(" NS2.Example.net ")
                .unwrap()
                .to_string(),
            "ns2.example.net:53"
        );
        assert_eq!(
            normalize_secondary_address("ns2.example.net.")
                .unwrap()
                .to_string(),
            "ns2.example.net:53"
        );
        assert_eq!(
            normalize_secondary_address("192.0.2.7")
                .unwrap()
                .to_string(),
            "192.0.2.7:53"
        );
        assert_eq!(
            normalize_secondary_address("2001:db8::7")
                .unwrap()
                .to_string(),
            "[2001:db8::7]:53"
        );
        assert_eq!(
            normalize_secondary_address("[2001:db8::7]:5300")
                .unwrap()
                .to_string(),
            "[2001:db8::7]:5300"
        );
    }

    /// Verify that `normalize_secondary_address` rejects an entry that is not an address target.
    #[test]
    fn normalize_secondary_address_rejects_an_entry_that_is_not_an_address_target() {
        for address in ["", "not a host", "ns2.example.net:port", "192.0.2.7:0"] {
            let err = normalize_secondary_address(address).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{address:?}");
        }
    }
}
