use chrono::Utc;

use super::{DnssecDenial, Zone};
use crate::{
    dns::name::{OwnerName, ZoneName},
    model::record::RecordType,
};

fn test_zone() -> Zone {
    Zone {
        id: 1,
        name: ZoneName::from_row("example.com"),
        mname: "ns1.example.com".to_string(),
        rname: "hostmaster@example.com".to_string(),
        default_ttl: 3600,
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum_ttl: 86400,
        dnssec_denial: DnssecDenial::Nsec,
        created_at: Utc::now(),
    }
}

#[test]
fn is_mname_matches_the_apex_ns_naming_mname() {
    let zone = test_zone();

    assert!(zone.is_mname(&RecordType::NS, &OwnerName::apex(), "ns1.example.com"));
    // Trailing-dot and case differences name the same host.
    assert!(zone.is_mname(&RecordType::NS, &OwnerName::apex(), "NS1.Example.Com."));
    // These take the stored owner name, which is relative and holds the apex
    // as the empty name; a spelled-out zone name is a label under it.
    assert!(!zone.is_mname(
        &RecordType::NS,
        &OwnerName::from_row("example.com."),
        "ns1.example.com"
    ));
}

#[test]
fn is_mname_rejects_other_rows() {
    let zone = test_zone();

    assert!(!zone.is_mname(&RecordType::NS, &OwnerName::apex(), "ns2.example.com"));
    assert!(!zone.is_mname(
        &RecordType::NS,
        &OwnerName::from_row("sub"),
        "ns1.example.com"
    ));
    assert!(!zone.is_mname(&RecordType::A, &OwnerName::apex(), "ns1.example.com"));
}

#[test]
fn mname_record_builds_the_apex_row_for_the_zone() {
    let zone = test_zone();
    let record = zone.mname_record(600);

    assert!(zone.is_mname(&record.record_type, &record.name, &record.value));
    assert!(record.name.is_apex());
    assert_eq!(record.ttl, 600);
    assert_eq!(record.zone_id, zone.id);
    assert_eq!(record.priority, None);
}
