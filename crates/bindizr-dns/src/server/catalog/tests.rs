use bindizr_core::{dns::name::ZoneName, model::zone::DnssecDenial};

use super::*;

#[test]
fn catalog_digest_changes_when_members_change() {
    let zones = vec![
        Zone {
            id: 1,
            name: ZoneName::from_row("example.com"),
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            default_ttl: 3600,
            serial: 100,
            refresh: 3600,
            retry: 3600,
            expire: 604800,
            minimum_ttl: 3600,
            dnssec_denial: DnssecDenial::Nsec,
            created_at: Utc::now(),
        },
        Zone {
            id: 2,
            name: ZoneName::from_row("test.com"),
            mname: "ns1.test.com".to_string(),
            rname: "admin.test.com".to_string(),
            default_ttl: 3600,
            serial: 200,
            refresh: 3600,
            retry: 3600,
            expire: 604800,
            minimum_ttl: 3600,
            dnssec_denial: DnssecDenial::Nsec,
            created_at: Utc::now(),
        },
    ];

    let member_zones = zones
        .iter()
        .map(|zone| zone.name.to_string())
        .collect::<Vec<_>>();
    let original = catalog_digest(&member_zones, &zones);
    let updated_members = vec!["example.com".to_string()];

    assert_ne!(original, catalog_digest(&updated_members, &zones));
}
