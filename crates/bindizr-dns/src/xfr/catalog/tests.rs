use super::*;

#[test]
fn is_catalog_zone_matches_catalog_name() {
    assert!(is_catalog_zone("catalog.bind"));
    assert!(!is_catalog_zone("example.com"));
    assert!(!is_catalog_zone("catalog.example.com"));
}

#[test]
fn zone_name_to_member_id_is_stable_and_dns_safe() {
    assert_eq!(zone_name_to_member_id("example.com"), "example-com");
    assert_eq!(zone_name_to_member_id("api.example.com"), "api-example-com");
    assert_eq!(zone_name_to_member_id("test.co.uk"), "test-co-uk");
}

#[test]
fn catalog_signature_changes_when_members_change() {
    let zones = vec![
        Zone {
            id: 1,
            name: "example.com".to_string(),
            primary_ns: "ns1.example.com".to_string(),
            admin_email: "admin.example.com".to_string(),
            ttl: 3600,
            serial: 100,
            refresh: 3600,
            retry: 3600,
            expire: 604800,
            minimum_ttl: 3600,
            created_at: Utc::now(),
        },
        Zone {
            id: 2,
            name: "test.com".to_string(),
            primary_ns: "ns1.test.com".to_string(),
            admin_email: "admin.test.com".to_string(),
            ttl: 3600,
            serial: 200,
            refresh: 3600,
            retry: 3600,
            expire: 604800,
            minimum_ttl: 3600,
            created_at: Utc::now(),
        },
    ];

    let member_zones = zones
        .iter()
        .map(|zone| zone.name.clone())
        .collect::<Vec<_>>();
    let original = catalog_signature(&member_zones, &zones);
    let updated_members = vec!["example.com".to_string()];

    assert_ne!(original, catalog_signature(&updated_members, &zones));
}
