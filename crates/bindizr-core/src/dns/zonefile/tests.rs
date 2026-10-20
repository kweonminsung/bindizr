//! Master-file and AXFR import parsing, including names, values, and errors.

use domain::{
    base::rdata::ComposeRecordData,
    zonefile::inplace::{Entry, Zonefile},
};

use super::*;
use crate::dns::{name::ZoneName, query::TransferRecord, record::Rdata};

/// Preserve TXT octets that cannot be represented as UTF-8 segments.
#[test]
fn txt_preserves_non_utf8_octets() {
    let parsed = ParsedZoneFile::parse(
        r#"weird IN TXT "\255\254""#,
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(3600).unwrap(),
    );
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(
        parsed.records[0].value,
        ZoneFileValue::Rdata(r#""\255\254""#.into())
    );
}

/// Read a known type spelled generically as that type (RFC 3597, Section 5),
/// and refuse octets that do not encode it.
#[test]
fn parse_reads_generic_rdata_of_known_types() {
    let zone = ZoneName::parse("example.com").unwrap();
    let parsed = ParsedZoneFile::parse(
        "www IN A \\# 4 c0000201\nmail IN MX \\# 20 000a 046d61696c 076578616d706c65 03636f6d 00\n",
        &zone,
        Ttl::try_from(3600).unwrap(),
    );
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(
        parsed.records[0].value,
        ZoneFileValue::Rdata("192.0.2.1".into())
    );
    assert_eq!(parsed.records[0].record_type, RecordType::A);
    assert_eq!(parsed.records[1].record_type, RecordType::Mx);
    assert_eq!(
        parsed.records[1].value,
        ZoneFileValue::Rdata("mail.example.com.".into())
    );
    assert_eq!(parsed.records[1].priority, Some(10));

    let parsed = ParsedZoneFile::parse(
        "www IN A \\# 3 c00002\n",
        &zone,
        Ttl::try_from(3600).unwrap(),
    );
    assert!(
        parsed
            .errors
            .iter()
            .any(|e| e.contains("does not encode a A record")),
        "{:?}",
        parsed.errors
    );
}

/// Verify that parse error names the line of the submitted text.
#[test]
fn parse_error_names_the_line_of_the_submitted_text() {
    // An unknown rtype is caught where it sits; an rdata error is reported
    // at the end of the entry, which would blur what this pins down.
    let parsed = ParsedZoneFile::parse(
        "ok IN A 192.0.2.1\nbad !!! IN A 192.0.2.2\n",
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(3600).unwrap(),
    );
    assert!(
        parsed.errors.iter().any(|e| e.contains(": 2:")),
        "expected the error to name line 2, got: {:?}",
        parsed.errors
    );
}

/// Verify that TXT UTF8 multi segment parses as segments.
#[test]
fn txt_parser_preserves_utf8_segments() {
    let parsed = ParsedZoneFile::parse(
        "multi IN TXT \"foo\" \"bar\"\n",
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(3600).unwrap(),
    );
    assert!(
        parsed.errors.is_empty(),
        "unexpected errors: {:?}",
        parsed.errors
    );
    let record = parsed
        .records
        .iter()
        .find(|record| record.record_type == RecordType::Txt)
        .expect("a TXT record");
    match &record.value {
        ZoneFileValue::Segments(segments) => assert_eq!(segments, &["foo", "bar"]),
        other => panic!("expected segments, got {other:?}"),
    }
}

/// Verify that a TTL written with a BIND unit suffix is refused on its line.
#[test]
fn zonefile_rejects_ttl_units() {
    // RFC 1035, Section 5.1 defines the TTL as a decimal integer; the suffix
    // is a BIND extension, and `named-compilezone` writes it back as seconds.
    let parsed = ParsedZoneFile::parse(
        "www IN A 192.0.2.1\nmail 1h IN A 192.0.2.2\n",
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(300).unwrap(),
    );

    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.errors.len(), 1, "{:?}", parsed.errors);
    assert!(
        parsed.errors[0].starts_with("failed to parse zone file: 2:"),
        "{}",
        parsed.errors[0]
    );
}

/// Verify zone-file parsing of NAPTR presentation data.
#[test]
fn zonefile_preserves_naptr_presentation() {
    // `domain` renders a root replacement as `..`, so the value comes from
    // the parsed fields rather than its display form.
    let parsed = ParsedZoneFile::parse(
        concat!(
            "tel IN NAPTR 200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .\n",
            "sip IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.Example.COM.\n",
        ),
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(300).unwrap(),
    );

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    let values: Vec<_> = parsed.records.iter().map(|record| &record.value).collect();
    assert_eq!(
        values,
        [
            &ZoneFileValue::Rdata("200 20 \"u\" \"E2U+tel\" \"!^.*$!tel:+1!\" .".to_string()),
            &ZoneFileValue::Rdata(
                "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.Example.COM.".to_string()
            ),
        ]
    );
}

/// Verify that only the apex SOA is read as the zone's own.
#[test]
fn zonefile_rejects_non_apex_soa() {
    // `zone import --create` builds the new zone from `soa`, so a foreign
    // owner's SOA would hand it that zone's serial, MNAME, RNAME and timers.
    let parsed = ParsedZoneFile::parse(
        "other.example. IN SOA ns1.other.example. host.other.example. (99 1 2 3 4)\n\
         www IN A 192.0.2.1\n",
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(3600).unwrap(),
    );
    assert!(
        parsed.soa.is_none(),
        "a foreign SOA was read as the zone's own"
    );
    assert!(
        parsed
            .errors
            .iter()
            .any(|e| e.contains("does not belong to zone")),
        "{:?}",
        parsed.errors
    );

    let parsed = ParsedZoneFile::parse(
        "@ IN SOA ns1.example.com. host.example.com. (99 1 2 3 4)\n",
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(3600).unwrap(),
    );
    assert_eq!(parsed.soa.expect("apex SOA").serial, Serial::from(99));
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);

    // Two apex SOAs leave the serial and timers ambiguous, so taking the first
    // would settle the zone by line order.
    let parsed = ParsedZoneFile::parse(
        "@ IN SOA ns1.example.com. host.example.com. (99 1 2 3 4)\n\
         @ IN SOA ns2.example.com. host.example.com. (7 1 2 3 4)\n",
        &ZoneName::parse("example.com").unwrap(),
        Ttl::try_from(3600).unwrap(),
    );
    assert!(
        parsed
            .errors
            .iter()
            .any(|e| e.contains("more than one SOA")),
        "{:?}",
        parsed.errors
    );
}

/// Build one transferred record with uncompressed wire RDATA.
fn transfer_record(name: &str, rtype: Rtype, rdata: &str) -> TransferRecord {
    let mut zonefile = Zonefile::new();
    zonefile.extend_from_slice(format!("{name} 300 IN {rtype} {rdata}\n").as_bytes());
    let Entry::Record(record) = zonefile.next_entry().unwrap().unwrap() else {
        panic!("record");
    };
    let mut bytes = Vec::new();
    let Ok(()) = record.data().compose_rdata(&mut bytes);
    TransferRecord {
        name: crate::dns::name::to_fqdn(&record.owner().to_string()),
        rtype,
        ttl: 300,
        rdata: Rdata::new(bytes).unwrap(),
    }
}

/// Keep the opening SOA and discard its closing delimiter.
#[test]
fn transfer_keeps_one_soa_for_creation() {
    // The closing SOA is a transfer delimiter, not a second zone definition.
    const SOA: &str = "ns1.example.com. admin.example.com. 7 300 60 3600000 86400";
    let records = [
        transfer_record("example.com.", Rtype::SOA, SOA),
        transfer_record("www.example.com.", Rtype::A, "192.0.2.1"),
        transfer_record("example.com.", Rtype::SOA, SOA),
    ];

    let parsed = ParsedZoneFile::from_transfer(&records, &ZoneName::parse("example.com").unwrap());

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(parsed.soa.expect("the opening SOA").serial, Serial::from(7));
    // The SOA is the zone's own, never one of its records.
    assert_eq!(parsed.records.len(), 1);
}

/// Unsupported ordinary types reject the transferred zone.
#[test]
fn transfer_rejects_unsupported_ordinary_types() {
    let records = [
        transfer_record("www.example.com.", Rtype::A, "192.0.2.1"),
        transfer_record("example.com.", Rtype::HINFO, r#""rfc" "8482""#),
    ];

    let parsed = ParsedZoneFile::from_transfer(&records, &ZoneName::parse("example.com").unwrap());

    assert_eq!(parsed.records.len(), 1);
    assert!(parsed.errors.iter().any(|error| error.contains("HINFO")));
}

/// Wire conversion preserves label boundaries.
#[test]
fn transfer_preserves_escaped_names() {
    let records = [
        (r"a\.b.example.com.", Rtype::CNAME, "target.example.com."),
        (r"0/25.example.com.", Rtype::NS, "ns.example.com."),
        (
            "rfc.example.com.",
            Rtype::CNAME,
            "1.0/25.2.0.192.in-addr.arpa.",
        ),
        ("example.com.", Rtype::CAA, r#"0 issue "a\"b\\c""#),
    ]
    .map(|(name, rtype, rdata)| transfer_record(name, rtype, rdata));

    let parsed = ParsedZoneFile::from_transfer(&records, &ZoneName::parse("example.com").unwrap());

    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    let carried: Vec<_> = parsed
        .records
        .iter()
        .map(|record| (record.owner_fqdn.as_str(), &record.value))
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

/// Preserve TXT segments and root targets across import sources.
#[test]
fn transfer_preserves_record_values_and_arbitrary_octets() {
    let zone = ZoneName::parse("example.com").unwrap();
    let records = [
        transfer_record(
            "txt.example.com.",
            Rtype::TXT,
            r#""Mixed CASE" "a\"b\\c" """#,
        ),
        transfer_record("srv.example.com.", Rtype::SRV, "10 5 5060 ."),
        transfer_record(
            "naptr.example.com.",
            Rtype::NAPTR,
            r#"10 20 "U" "E2U+sip" "!^.*$!sip:a@example.net!" ."#,
        ),
        transfer_record("example.com.", Rtype::MX, "0 ."),
    ];
    let parsed = ParsedZoneFile::from_transfer(&records, &zone);
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert_eq!(
        parsed.records[0].value,
        ZoneFileValue::Segments(vec!["Mixed CASE".into(), "a\"b\\c".into(), "".into()])
    );
    assert_eq!(
        parsed.records[1].value,
        ZoneFileValue::Rdata("5 5060 .".into())
    );
    assert_eq!(parsed.records[1].priority, Some(10));
    assert!(
        matches!(&parsed.records[2].value, ZoneFileValue::Rdata(value) if value.ends_with(" ."))
    );
    assert_eq!(parsed.records[3].value, ZoneFileValue::Rdata(".".into()));
    assert_eq!(parsed.records[3].priority, Some(0));
    let text = ParsedZoneFile::parse("@ 300 IN MX 0 .\n", &zone, Ttl::try_from(300).unwrap());
    assert_eq!(text.records, parsed.records[3..]);

    let invalid = TransferRecord {
        name: "txt.example.com.".into(),
        rtype: Rtype::TXT,
        ttl: 300,
        rdata: Rdata::new(vec![1, 255]).unwrap(),
    };
    let parsed = ParsedZoneFile::from_transfer(&[invalid], &zone);
    assert!(parsed.errors.is_empty());
    assert_eq!(
        parsed.records[0].value,
        ZoneFileValue::Rdata(r#""\255""#.into())
    );
}

/// Match closing SOA case-insensitively without changing received RDATA.
#[test]
fn transfer_import_accepts_case_varied_closing_soa() {
    let zone = ZoneName::parse("example.com").unwrap();
    let opening = transfer_record(
        "example.com.",
        Rtype::SOA,
        "NS1.Example.COM. Hostmaster.Example.COM. 42 7200 3600 604800 300",
    );
    let closing = transfer_record(
        "EXAMPLE.COM.",
        Rtype::SOA,
        "ns1.example.com. hostmaster.example.com. 42 7200 3600 604800 300",
    );
    let original = opening.rdata.clone();
    let records = [
        opening,
        transfer_record("example.com.", Rtype::NS, "ns1.example.com."),
        closing,
    ];
    let parsed = ParsedZoneFile::from_transfer(&records, &zone);
    assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
    assert!(parsed.soa.is_some());
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(records[0].rdata, original);
}
