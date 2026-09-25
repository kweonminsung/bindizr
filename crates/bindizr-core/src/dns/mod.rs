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

/// A stored serial as the wire carries it (RFC 1035 SOA SERIAL is unsigned).
/// Rows are stored as `i32`, so a negative one is corrupt data.
pub fn serial_to_u32(serial: i32) -> Result<u32, String> {
    u32::try_from(serial).map_err(|_| format!("Invalid DNS serial: {}", serial))
}

/// A wire serial as a row stores it; one past `i32::MAX` names nothing
/// bindizr could have written, so it is refused as input.
pub fn serial_to_i32(serial: u32) -> Result<i32, String> {
    i32::try_from(serial).map_err(|_| {
        format!(
            "serial {} is beyond the stored range of {}",
            serial,
            i32::MAX
        )
    })
}
