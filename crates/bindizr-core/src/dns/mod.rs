pub mod name;
pub mod record;
pub mod txt;

/// Well-known name of the BIND catalog zone (RFC 9432).
pub const CATALOG_ZONE_NAME: &str = "catalog.bind";

/// Whether `zone_name` is the virtual RFC 9432 catalog zone.
pub fn is_catalog_zone(zone_name: &str) -> bool {
    zone_name == CATALOG_ZONE_NAME
}
