use sha2::{Digest, Sha256};

/// Well-known name of the BIND catalog zone (RFC 9432).
pub const CATALOG_ZONE_NAME: &str = "catalog.bind";

/// Whether `zone_name` is the virtual RFC 9432 catalog zone. Case-insensitive
/// per RFC 4343; callers pass client-cased query names as-is.
pub fn is_catalog_zone(zone_name: &str) -> bool {
    zone_name.eq_ignore_ascii_case(CATALOG_ZONE_NAME)
}

/// A member zone's unique-id label (RFC 9432, Section 4.1): truncated
/// SHA-256, so any zone name fits one label and distinct names never collide.
pub(crate) fn zone_name_to_member_id(zone_name: &str) -> String {
    // Case-insensitive per RFC 4343, matching the catalog digest.
    let digest = Sha256::digest(zone_name.to_ascii_lowercase().as_bytes());
    hex::encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_name_to_member_id_is_stable_and_case_insensitive() {
        let id = zone_name_to_member_id("example.com");
        assert_eq!(id, zone_name_to_member_id("example.com"));
        assert_eq!(id, zone_name_to_member_id("EXAMPLE.COM"));
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn zone_name_to_member_id_fits_a_label_for_the_longest_zone_name() {
        // RFC 9432, Section 4.1: the id is one label, so the longest zone
        // name must still fit under the 63-byte label cap.
        let long = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(long.len(), 253);
        assert!(zone_name_to_member_id(&long).len() <= 63);
    }

    #[test]
    fn zone_name_to_member_id_distinguishes_dot_from_dash() {
        // RFC 9432, Section 4.1 requires unique ids.
        assert_ne!(
            zone_name_to_member_id("a.b.example.com"),
            zone_name_to_member_id("a-b.example.com")
        );
    }

    #[test]
    fn is_catalog_zone_ignores_ascii_case() {
        assert!(is_catalog_zone("catalog.bind"));
        assert!(is_catalog_zone("CATALOG.BIND"));
        assert!(is_catalog_zone("Catalog.Bind"));
        assert!(!is_catalog_zone("catalog.bind.example"));
    }
}
