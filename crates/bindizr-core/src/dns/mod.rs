pub mod address;
mod catalog_zone;
pub mod dnssec;
pub mod message;
pub mod name;
pub mod nsupdate;
pub mod query;
pub mod record;
mod serial;
pub mod tsig;
mod ttl;
pub mod zonefile;

pub(crate) use catalog_zone::zone_name_to_member_id;
pub use serial::{ConvertSerialError, Serial};
pub use ttl::{ConvertTtlError, Ttl};

/// Maximum size of a DNS message carried over TCP (16-bit length prefix,
/// RFC 1035, Section 4.2.2). The record-value size caps derive from it.
pub(crate) const DNS_TCP_MAX_SIZE: usize = 65_535;

/// An error of the `domain` crate, carried boxed: its error types vary across
/// versions and nothing here matches on them, so only the chain is kept.
pub type LibraryError = Box<dyn std::error::Error + Send + Sync + 'static>;
