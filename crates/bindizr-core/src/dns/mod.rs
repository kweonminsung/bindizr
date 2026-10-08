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

use std::time::Duration;

pub(crate) use catalog_zone::zone_name_to_member_id;
pub use serial::{ConvertSerialError, Serial};
pub use soa_interval::{ConvertSoaIntervalError, SoaInterval};
pub use ttl::{ConvertTtlError, Ttl};

/// Maximum size of a DNS message carried over TCP (16-bit length prefix,
/// RFC 1035, Section 4.2.2). The record-value size caps derive from it.
pub const DNS_TCP_MAX_SIZE: usize = 65_535;

/// How long a TCP connection may sit idle between queries; advertised to an
/// EDNS client as the edns-tcp-keepalive timeout (RFC 7828, Section 3.3.2).
pub const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// An error of the `domain` crate, carried boxed: its error types vary across
/// versions and nothing here matches on them, so only the chain is kept.
pub type LibraryError = Box<dyn std::error::Error + Send + Sync + 'static>;
