//! Unit tests of the DNS harness itself: the response parser the e2e assertions rely on.

use std::str::FromStr;

use domain::{
    base::{
        MessageBuilder, Name, Record, Ttl, UnknownRecordData,
        iana::{Class, Rcode},
    },
    rdata::{A, Cname, Mx, Srv, Txt},
};
use serde_json::{Value, json};

use super::*;

/// Verify that parse DNS response renders values in harness comparison format.
#[test]
fn extract_dns_records_renders_values_in_harness_comparison_format() {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(7);
    builder.header_mut().set_qr(true);

    let owner = Name::<Vec<u8>>::from_str("www.example.com").unwrap();
    let target = Name::<Vec<u8>>::from_str("mail.example.com").unwrap();
    let ttl = Ttl::from_secs(300);

    let mut answer = builder.answer();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            A::from_octets(192, 0, 2, 1),
        ))
        .unwrap();
    answer
        .push(Record::new(&owner, Class::IN, ttl, Mx::new(5, &target)))
        .unwrap();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            Srv::new(1, 2, 8080, &target),
        ))
        .unwrap();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            Txt::<Vec<u8>>::build_from_slice(b"hello").unwrap(),
        ))
        .unwrap();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            Txt::from_octets(vec![2, b'a', b'b', 1, b'c']).unwrap(),
        ))
        .unwrap();

    for rdata in [
        b"\x00\x05issue".as_slice(),
        b"\x80\x06custom\x00\xFF\x0A\"\\",
    ] {
        answer
            .push(Record::new(
                &owner,
                Class::IN,
                ttl,
                UnknownRecordData::from_octets(Rtype::CAA, rdata).unwrap(),
            ))
            .unwrap();
    }

    let escaped = Name::<Vec<u8>>::from_str(r"a\046b.\255.caf\195\169.\;meta.example").unwrap();
    answer
        .push(Record::new(&owner, Class::IN, ttl, Cname::new(&escaped)))
        .unwrap();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            ttl,
            Txt::from_octets(vec![2, 0, 255, 1, 195, 1, 169, 0]).unwrap(),
        ))
        .unwrap();

    for bytes in [
        b"".as_slice(),
        &[0, 255, 192, 12],
        &[192, 0, 2, 1, 6, 0x81, 0x80],
    ] {
        answer
            .push(Record::new(
                &owner,
                Class::IN,
                ttl,
                UnknownRecordData::from_octets(Rtype::from_int(65280), bytes).unwrap(),
            ))
            .unwrap();
    }

    let records = extract_dns_records(7, &answer.finish()).unwrap();
    let values: Vec<(u16, Option<Value>)> = records
        .into_iter()
        .map(|answer| (answer.record_type, answer.value))
        .collect();

    assert_eq!(
        values,
        vec![
            (1, Some(json!("192.0.2.1"))),
            (15, Some(json!("5 mail.example.com."))),
            (33, Some(json!("1 2 8080 mail.example.com."))),
            (16, Some(json!("hello"))),
            (16, Some(json!(["ab", "c"]))),
            (257, Some(json!(r#"0 issue """#))),
            (257, Some(json!(r#"128 custom "\000\255\010\"\\""#))),
            (5, Some(json!(r"a\046b.\255.caf\195\169.\;meta.example."))),
            (
                16,
                Some(json!({ "presentation": r#""\000\255" "\195" "\169" """# }))
            ),
            (65280, Some(json!(r"\# 0"))),
            (65280, Some(json!(r"\# 4 00FFC00C"))),
            (65280, Some(json!(r"\# 7 C0000201068180"))),
        ]
    );
}

/// Build a response containing the supplied WKS wire data without the production encoder.
fn build_wks_response(rdata: Vec<u8>) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(7);
    builder.header_mut().set_qr(true);

    let owner = Name::<Vec<u8>>::from_str("services.example.com").unwrap();
    let mut answer = builder.answer();
    answer
        .push(Record::new(
            &owner,
            Class::IN,
            Ttl::from_secs(300),
            UnknownRecordData::from_octets(Rtype::WKS, rdata).unwrap(),
        ))
        .unwrap();

    answer.finish()
}

/// WKS values match the API's numeric fields, including bitmap boundaries and empty services.
#[test]
fn extract_dns_records_decodes_wks_service_bitmaps() {
    // The captured BIND response advertises ports 22, 80, and 443.
    let mut observed = vec![0; 61];
    observed[..5].copy_from_slice(&[192, 0, 2, 1, 6]);
    observed[7] = 0x02;
    observed[15] = 0x80;
    observed[60] = 0x10;

    let mut highest_port = vec![0; 8197];
    highest_port[..5].copy_from_slice(&[192, 0, 2, 1, 255]);
    highest_port[8196] = 0x01;

    for (rdata, expected) in [
        (observed, "192.0.2.1 6 22 80 443"),
        (vec![192, 0, 2, 1, 0], "192.0.2.1 0"),
        (vec![192, 0, 2, 1, 6, 0x81, 0x80], "192.0.2.1 6 0 7 8"),
        (highest_port, "192.0.2.1 255 65535"),
    ] {
        let records = extract_dns_records(7, &build_wks_response(rdata)).unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, Rtype::WKS.to_int());
        assert_eq!(records[0].value, Some(json!(expected)));
    }
}

/// Incomplete fixed fields and service bits beyond port 65535 fail response decoding.
#[test]
fn extract_dns_records_rejects_invalid_wks_rdata() {
    for length in [0, 1, 2, 3, 4, 8198] {
        let response = build_wks_response(vec![0; length]);

        assert!(
            extract_dns_records(7, &response).is_err(),
            "accepted WKS rdata of length {length}"
        );
    }
}

/// Verify that a refused response includes the exact "REFUSED RCODE" text recognized by
/// `is_deleted_zone_absence`.
#[test]
fn extract_dns_records_names_refused_rcode_in_error() {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(9);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_rcode(Rcode::REFUSED);

    let error = extract_dns_records(9, &builder.finish()).unwrap_err();

    assert!(
        error.contains("REFUSED RCODE (5)"),
        "unexpected error: {error}"
    );
}

/// Verify that `extract_dns_records` treats nxdomain as no records.
#[test]
fn extract_dns_records_treats_nxdomain_as_no_records() {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(9);
    builder.header_mut().set_qr(true);
    builder.header_mut().set_rcode(Rcode::NXDOMAIN);

    let records = extract_dns_records(9, &builder.finish()).unwrap();

    assert!(records.is_empty());
}
