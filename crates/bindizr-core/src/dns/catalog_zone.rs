/// Well-known name of the BIND catalog zone (RFC 9432).
pub const CATALOG_ZONE_NAME: &str = "catalog.bind";

/// Whether `zone_name` is the virtual RFC 9432 catalog zone. Case-insensitive
/// per RFC 4343; callers pass client-cased query names as-is.
pub fn is_catalog_zone(zone_name: &str) -> bool {
    zone_name.eq_ignore_ascii_case(CATALOG_ZONE_NAME)
}

/// A member zone's catalog owner label (RFC 9432, Section 4.1).
pub fn zone_name_to_member_id(zone_name: &str) -> String {
    zone_name.replace('.', "-")
}

#[cfg(test)]
mod tests {
    #[test]
    fn zone_name_to_member_id_is_stable_and_dns_safe() {
        use super::zone_name_to_member_id;
        assert_eq!(zone_name_to_member_id("example.com"), "example-com");
        assert_eq!(zone_name_to_member_id("api.example.com"), "api-example-com");
        assert_eq!(zone_name_to_member_id("test.co.uk"), "test-co-uk");
    }

    use super::*;

    #[test]
    fn is_catalog_zone_ignores_ascii_case() {
        assert!(is_catalog_zone("catalog.bind"));
        assert!(is_catalog_zone("CATALOG.BIND"));
        assert!(is_catalog_zone("Catalog.Bind"));
        assert!(!is_catalog_zone("catalog.bind.example"));
    }
}
