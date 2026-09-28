use thiserror::Error;

pub mod address;
mod catalog_zone;
pub mod dnssec;
pub mod message;
pub mod name;
pub mod nsupdate;
pub mod query;
pub mod record;
pub mod tsig;
pub mod zonefile;

pub(crate) use catalog_zone::zone_name_to_member_id;

/// Maximum size of a DNS message carried over TCP (16-bit length prefix,
/// RFC 1035, Section 4.2.2). The record-value size caps derive from it.
pub(crate) const DNS_TCP_MAX_SIZE: usize = 65_535;

/// An error of the `domain` crate, carried boxed: its error types vary across
/// versions and nothing here matches on them, so only the chain is kept.
pub type LibraryError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A serial that cannot cross between its row form and its wire form.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConvertSerialError {
    /// Rows are stored as `i32`, so a negative one is corrupt data.
    #[error("Invalid DNS serial: {serial}")]
    Negative { serial: i32 },
    /// One past `i32::MAX` names nothing bindizr could have written.
    #[error("serial {serial} is beyond the stored range of {}", i32::MAX)]
    BeyondStoredRange { serial: u32 },
}

/// A stored serial as the wire carries it (RFC 1035 SOA SERIAL is unsigned).
pub fn serial_to_u32(serial: i32) -> Result<u32, ConvertSerialError> {
    u32::try_from(serial).map_err(|_| ConvertSerialError::Negative { serial })
}

/// A wire serial as a row stores it, refused as input when out of range.
pub fn serial_to_i32(serial: u32) -> Result<i32, ConvertSerialError> {
    i32::try_from(serial).map_err(|_| ConvertSerialError::BeyondStoredRange { serial })
}
