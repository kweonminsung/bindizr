use bindizr_core::dns::zonefile::{ParsedZoneFile, ZoneFileValue};

use super::*;

/// Build one transferred RR for the render tests.
fn transfer_rr(name: &str, rtype: Rtype, rdata: &str) -> TransferRr {
    TransferRr {
        name: name.to_string(),
        rtype,
        ttl: 300,
        rdata: rdata.to_string(),
    }
}

/// Verify that the render keeps the opening SOA and drops the closing one.
#[test]
fn a_rendered_transfer_keeps_one_soa_for_the_zone_to_be_created_from() {
    // `import --from-server --create` builds the zone from this SOA, and the
    // transfer's closing copy would read as a second one.
    const SOA: &str = "ns1.example.com. admin.example.com. 7 300 60 3600000 86400";
    let rrs = [
        transfer_rr("example.com.", Rtype::SOA, SOA),
        transfer_rr("www.example.com.", Rtype::A, "192.0.2.1"),
        transfer_rr("example.com.", Rtype::SOA, SOA),
    ];

    let parsed = ParsedZoneFile::parse(&render_zone_file(&rrs), "example.com", 300);

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(parsed.soa.expect("the opening SOA").serial, 7);
    // The SOA is the zone's own, never one of its records.
    assert_eq!(parsed.rrs.len(), 1);
}

/// Verify that a type bindizr cannot store reaches the parser as unsupported.
#[test]
fn a_type_the_render_cannot_store_is_left_for_skip_unsupported() {
    // Refusing it in the render would fail the import before
    // `--skip-unsupported` could pass over it.
    let rrs = [
        transfer_rr("www.example.com.", Rtype::A, "192.0.2.1"),
        transfer_rr("example.com.", Rtype::HINFO, r#""rfc" "8482""#),
    ];

    let parsed = ParsedZoneFile::parse(&render_zone_file(&rrs), "example.com", 300);

    assert_eq!(parsed.rrs.len(), 1);
    assert_eq!(parsed.unsupported.len(), 1, "{:?}", parsed.unsupported);
    assert!(
        parsed.unsupported[0].contains("HINFO"),
        "{:?}",
        parsed.unsupported
    );
}

/// The fetch goes structured RR -> text -> parsed record, so the render and
/// the parser must agree on RFC 1035, Section 5.1 escaping or a label splits.
#[test]
fn a_rendered_transfer_parses_back_into_the_names_it_carried() {
    let rrs = [
        (r"a\.b.example.com.", Rtype::CNAME, "target.example.com."),
        (r"0/25.example.com.", Rtype::NS, "ns.example.com."),
        (
            "rfc.example.com.",
            Rtype::CNAME,
            "1.0/25.2.0.192.in-addr.arpa.",
        ),
        ("example.com.", Rtype::CAA, r#"0 issue "a\"b\\c""#),
    ]
    .map(|(name, rtype, rdata)| TransferRr {
        name: name.to_string(),
        rtype,
        ttl: 300,
        rdata: rdata.to_string(),
    });

    let parsed = ParsedZoneFile::parse(&render_zone_file(&rrs), "example.com", 300);

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert!(parsed.unsupported.is_empty(), "{:?}", parsed.unsupported);
    let carried: Vec<_> = parsed
        .rrs
        .iter()
        .map(|rr| (rr.owner_fqdn.as_str(), &rr.value))
        .collect();
    assert_eq!(
        carried,
        [
            (
                r"a\046b.example.com.",
                &ZoneFileValue::Rdata("target.example.com.".to_string())
            ),
            (
                "0/25.example.com.",
                &ZoneFileValue::Rdata("ns.example.com.".to_string())
            ),
            (
                "rfc.example.com.",
                &ZoneFileValue::Rdata("1.0/25.2.0.192.in-addr.arpa.".to_string())
            ),
            (
                "example.com.",
                &ZoneFileValue::Rdata(r#"0 issue "a\"b\\c""#.to_string())
            ),
        ]
    );
}
