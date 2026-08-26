mod catalog_zone;
pub mod dnssec;
pub mod message;
pub mod name;
pub mod nsupdate;
pub mod query;
pub mod record;
pub mod zonefile;

pub(crate) use catalog_zone::zone_name_to_member_id;
pub use catalog_zone::{CATALOG_ZONE_NAME, is_catalog_zone};

/// Maximum size of a DNS message carried over TCP (16-bit length prefix,
/// RFC 1035, Section 4.2.2). The record-value size caps derive from it.
pub const DNS_TCP_MAX_SIZE: usize = 65_535;

/// A stored serial as the wire carries it (RFC 1035 SOA SERIAL is unsigned).
pub fn serial_to_u32(serial: i32) -> Result<u32, String> {
    u32::try_from(serial).map_err(|_| format!("Invalid DNS serial: {}", serial))
}
