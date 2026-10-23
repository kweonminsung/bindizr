pub mod address;
mod catalog_zone;
pub mod dnssec;
pub mod message;
pub mod name;
pub mod nsupdate;
pub mod query;
pub mod record;
mod serial;
mod soa_interval;
pub mod tsig;
mod ttl;
pub mod zonefile;

pub use catalog_zone::{CatalogZone, ExtractMemberZonesError, extract_member_zones};
pub(crate) use catalog_zone::{MAX_CATALOG_ZONE_WIRE_LEN, catalog_member_owner_name};
pub use serial::{ConvertSerialError, Serial};
pub use soa_interval::{ConvertSoaIntervalError, SoaInterval};
pub use ttl::{ConvertTtlError, Ttl};

/// SOA REFRESH of the generated catalog, also bounding its NOTIFY batching delay.
pub const CATALOG_SOA_REFRESH: SoaInterval = SoaInterval::from_secs(3_600);

/// Maximum size of a DNS message carried over TCP (16-bit length prefix,
/// RFC 1035, Section 4.2.2). The record-value size caps derive from it.
pub const DNS_TCP_MAX_SIZE: usize = 65_535;

/// An error of the `domain` crate, carried boxed: its error types vary across
/// versions and nothing here matches on them, so only the chain is kept.
pub type LibraryError = Box<dyn std::error::Error + Send + Sync + 'static>;
