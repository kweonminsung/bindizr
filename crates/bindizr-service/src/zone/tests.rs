use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::apex_ns_rrset_ttl;
use crate::model::{
    record::RecordType,
    zone::{DnssecDenial, Zone},
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
fn apex_ns_rrset_ttl_joins_the_existing_apex_ns_rrset() {
    let zone = test_zone();

    // The first apex NS wins, so callers express their own priority by the
    // order they chain candidate sources.
    assert_eq!(
        apex_ns_rrset_ttl(
            &zone,
            [
                (&RecordType::A, &OwnerName::apex(), 60),
                (&RecordType::NS, &OwnerName::from_row("sub"), 120),
                (&RecordType::NS, &OwnerName::apex(), 900),
                (&RecordType::NS, &OwnerName::apex(), 1800),
            ]
        ),
        900
    );
}

#[test]
fn apex_ns_rrset_ttl_falls_back_to_the_zone_ttl() {
    let zone = test_zone();

    assert_eq!(apex_ns_rrset_ttl(&zone, []), zone.default_ttl);
    // Only apex NS rows share the RRset a synthesized row would join.
    assert_eq!(
        apex_ns_rrset_ttl(
            &zone,
            [
                (&RecordType::A, &OwnerName::apex(), 60),
                (&RecordType::NS, &OwnerName::from_row("sub"), 120)
            ]
        ),
        zone.default_ttl
    );
}
