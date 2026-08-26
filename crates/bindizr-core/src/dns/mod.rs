mod catalog_zone;
pub mod dnssec;
pub mod name;
pub mod record;
pub mod zonefile;

pub use catalog_zone::{CATALOG_ZONE_NAME, is_catalog_zone};

/// Maximum size of a DNS message carried over TCP (16-bit length prefix,
/// RFC 1035, Section 4.2.2). The record-value size caps derive from it.
pub const DNS_TCP_MAX_SIZE: usize = 65_535;
