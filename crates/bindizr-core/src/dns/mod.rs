pub mod name;
pub mod record;
pub mod txt;

/// Well-known name of the BIND catalog zone (RFC 9432).
pub const CATALOG_ZONE_NAME: &str = "catalog.bind";

/// Whether `zone_name` is the virtual RFC 9432 catalog zone. Case-insensitive
/// per RFC 4343; callers pass client-cased query names as-is.
pub fn is_catalog_zone(zone_name: &str) -> bool {
    zone_name.eq_ignore_ascii_case(CATALOG_ZONE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_catalog_zone_ignores_ascii_case() {
        assert!(is_catalog_zone("catalog.bind"));
        assert!(is_catalog_zone("CATALOG.BIND"));
        assert!(is_catalog_zone("Catalog.Bind"));
        assert!(!is_catalog_zone("catalog.bind.example"));
    }
}
