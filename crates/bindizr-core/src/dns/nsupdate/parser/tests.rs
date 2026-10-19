use super::*;
use crate::{
    dns::message::{Class, Edns, Rtype},
    model::record::RecordType,
};

/// Decode compressed SOA names and unsigned fields without crossing RDLENGTH.
#[test]
fn soa_update_decodes_compression_and_checks_rdata_length() {
    let mut message = minimal_update_with_ztype(6);
    let start = message.len();
    message.extend_from_slice(&[3, b'n', b's', b'1', 0xc0, 12]);
    message.extend_from_slice(&[
        11, b'h', b'o', b's', b't', b'.', b'm', b'a', b's', b't', b'e', b'r', 0xc0, 12,
    ]);
    for field in [u32::MAX, 7200, 3600, 604800, 86400] {
        message.extend_from_slice(&field.to_be_bytes());
    }
    let mut record = UpdateRecord {
        name: "example.com.".to_string(),
        record_type: Rtype::SOA,
        class: Class::IN,
        ttl: 300,
        rdata: message[start..].to_vec(),
        rdata_start: start,
    };
    let soa = record.to_soa_value(&message).unwrap();
    assert_eq!(soa.mname, "ns1.example.com.");
    assert_eq!(soa.rname, r"host\046master.example.com.");
    assert_eq!(soa.serial, u32::MAX);
    assert_eq!(
        [soa.refresh, soa.retry, soa.expire, soa.minimum],
        [7200, 3600, 604800, 86400]
    );
    let length = record.rdata.len();
    for length in 0..length {
        record.rdata.truncate(length);
        assert!(record.to_soa_value(&message).is_err());
        record.rdata = message[start..].to_vec();
    }
    record.rdata.push(0);
    message.push(0);
    assert!(record.to_soa_value(&message).is_err());
}

/// Build a minimal UPDATE message with the requested zone type.
pub(crate) fn minimal_update_with_ztype(ztype: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&[
        0x12, 0x34, // ID
        0x28, 0x00, // Opcode UPDATE
        0x00, 0x01, // ZOCOUNT
        0x00, 0x00, // PRCOUNT
        0x00, 0x00, // UPCOUNT
        0x00, 0x00, // ADCOUNT
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
    ]);
    message.extend_from_slice(&ztype.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message
}

/// Set the additional-record count in a test DNS header.
fn set_arcount(message: &mut [u8], arcount: u16) {
    message[10..12].copy_from_slice(&arcount.to_be_bytes());
}

/// Append an EDNS OPT record to the test message.
fn append_opt_record(message: &mut Vec<u8>) {
    message.extend_from_slice(&[
        0x00, // Root owner name
        0x00, 0x29, // TYPE OPT
        0x04, 0xd0, // UDP payload size
        0x00, 0x00, 0x00, 0x00, // Extended RCODE, version, flags
        0x00, 0x00, // RDLEN
    ]);
}

/// Append a TSIG fixture with the default key name.
fn append_tsig_record(message: &mut Vec<u8>) {
    append_tsig_record_with_owner(message, &[0x03, b'k', b'e', b'y', 0x00]);
}

/// Append a TSIG fixture with the supplied owner name.
fn append_tsig_record_with_owner(message: &mut Vec<u8>, owner: &[u8]) {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&[
        0x0b, b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'2', b'5', b'6', 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, // Time signed
        0x01, 0x2c, // Fudge
        0x00, 0x20, // MAC size: the 32 octets hmac-sha256 produces
    ]);
    rdata.extend_from_slice(&[0u8; 32]);
    rdata.extend_from_slice(&[
        0x12, 0x34, // Original ID
        0x00, 0x00, // Error
        0x00, 0x00, // Other len
    ]);

    message.extend_from_slice(owner);
    message.extend_from_slice(&[
        0x00, 0xfa, // TYPE TSIG
        0x00, 0xff, // CLASS ANY
        0x00, 0x00, 0x00, 0x00, // TTL
    ]);
    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&rdata);
}

/// TSIG belongs only at the end of Additional (RFC 8945, Section 5.2),
/// even when a misplaced owner would fail a later zone or grant check.
#[test]
fn parse_update_request_rejects_tsig_in_prerequisite_and_update_sections() {
    for count_offset in [6, 8] {
        for owner in [&b"\xc0\x0c"[..], &b"\x03key\x00"[..]] {
            for additional_tsig in [false, true] {
                let mut message = minimal_update_with_ztype(6);
                message[count_offset..count_offset + 2].copy_from_slice(&1u16.to_be_bytes());
                append_tsig_record_with_owner(&mut message, owner);
                if additional_tsig {
                    set_arcount(&mut message, 1);
                    append_tsig_record(&mut message);
                }
                assert!(matches!(
                    UpdateRequest::parse(&message),
                    Err(ParseUpdateError::InvalidTsig)
                ));
            }
        }
    }
}

/// Reject non-SOA zone types before the service considers authority.
#[test]
fn parse_update_request_rejects_non_soa_zone_type() {
    for class in [Class::IN, Class::CH, Class::HS, Class::from_int(65280)] {
        let mut message = minimal_update_with_ztype(1);
        let class_start = message.len() - 2;
        message[class_start..].copy_from_slice(&class.to_int().to_be_bytes());
        let err = UpdateRequest::parse(&message).unwrap_err();
        assert!(matches!(err, ParseUpdateError::InvalidZoneSection));
    }
}

/// Preserve ZCLASS so the service can decide whether the zone is served.
#[test]
fn parse_update_request_preserves_zone_class() {
    for class in [
        Class::IN,
        Class::CH,
        Class::HS,
        Class::NONE,
        Class::ANY,
        Class::from_int(0),
        Class::from_int(65280),
        Class::from_int(u16::MAX),
    ] {
        let mut message = minimal_update_with_ztype(6);
        let class_start = message.len() - 2;
        message[class_start..].copy_from_slice(&class.to_int().to_be_bytes());
        let request = UpdateRequest::parse(&message).unwrap();
        assert_eq!(request.zone_name, "example.com.");
        assert_eq!(request.zone_class, class);
        for count in [0u16, 2] {
            message[4..6].copy_from_slice(&count.to_be_bytes());
            assert!(matches!(
                UpdateRequest::parse(&message),
                Err(ParseUpdateError::InvalidHeader)
            ));
        }
    }
}

/// A missing class field is malformed, not an unsupported zone class.
#[test]
fn parse_update_request_rejects_truncated_zone_class() {
    let message = minimal_update_with_ztype(6);
    for missing in [1, 2] {
        assert!(matches!(
            UpdateRequest::parse(&message[..message.len() - missing]),
            Err(ParseUpdateError::InvalidZoneSection)
        ));
    }
}

/// Verify that `UpdateRequest::parse` accepts opt additional without TSIG.
#[test]
fn parse_update_request_accepts_opt_additional_without_tsig() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    append_opt_record(&mut message);

    let request = UpdateRequest::parse(&message).unwrap();
    assert!(request.tsig.is_none());
}

/// Verify that `UpdateRequest::parse` accepts opt before TSIG.
#[test]
fn parse_update_request_accepts_opt_before_tsig() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 2);
    append_opt_record(&mut message);
    append_tsig_record(&mut message);

    let request = UpdateRequest::parse(&message).unwrap();
    let tsig = request.tsig.unwrap();
    assert_eq!(tsig.name, "key.");
    assert_eq!(tsig.fudge, 300);
}

/// Escaping keeps the one-label key name distinct from the multi-label name of
/// the same spelling, which decodes to different labels.
#[test]
fn parse_update_request_escapes_a_dot_inside_a_tsig_owner_label() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    append_tsig_record_with_owner(
        &mut message,
        &[
            0x0c, b'K', b'e', b'y', b'.', b'W', b'i', b't', b'h', b'.', b'D', b'o', b't', 0x00,
        ],
    );

    let request = UpdateRequest::parse(&message).unwrap();
    assert_eq!(request.tsig.unwrap().name, r"Key\046With\046Dot.");
}

/// The wire carries one label holding a dot; rendering it unescaped would let
/// it read as two and land the update in a zone it is not in.
#[test]
fn parse_update_request_escapes_a_dot_inside_a_zone_label() {
    let mut message = Vec::new();
    message.extend_from_slice(&[
        0x12, 0x34, // ID
        0x28, 0x00, // Opcode UPDATE
        0x00, 0x01, // ZOCOUNT
        0x00, 0x00, // PRCOUNT
        0x00, 0x00, // UPCOUNT
        0x00, 0x00, // ADCOUNT
        0x0c, b'e', b'v', b'i', b'l', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', // One label
        0x03, b'c', b'o', b'm', 0x00,
    ]);
    message.extend_from_slice(&6u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());

    let request = UpdateRequest::parse(&message).unwrap();
    assert_eq!(request.zone_name, r"evil\046example.com.");
}

/// Verify that `UpdateRequest::parse` rejects TSIG before other additional records.
#[test]
fn parse_update_request_rejects_tsig_before_other_additional_records() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 2);
    append_tsig_record(&mut message);
    append_opt_record(&mut message);

    let err = UpdateRequest::parse(&message).unwrap_err();
    assert!(matches!(err, ParseUpdateError::InvalidTsig));
}

/// Verify that `to_record_value` preserves TXT character string boundaries.
#[test]
fn to_record_value_preserves_txt_character_string_boundaries() {
    let first = UpdateRecord {
        name: "txt.example.com.".to_string(),
        record_type: Rtype::TXT,
        class: Class::IN,
        ttl: 300,
        rdata: vec![2, b'a', b'b', 1, b'c'],
        rdata_start: 0,
    };
    let second = UpdateRecord {
        name: "txt.example.com.".to_string(),
        record_type: Rtype::TXT,
        class: Class::IN,
        ttl: 300,
        rdata: vec![1, b'a', 2, b'b', b'c'],
        rdata_start: 0,
    };

    let (_, first_value, _) = first.to_record_value(&first.rdata).unwrap();
    let (_, second_value, _) = second.to_record_value(&second.rdata).unwrap();

    assert_ne!(first_value, second_value);
    assert!(!RecordType::Txt.values_equal(&first_value, None, &second_value, None));
}

/// Keep RDLENGTH-delimited values from consuming the following record or TSIG.
#[test]
fn variable_length_rdata_stops_before_the_next_record() {
    for (rtype, rdata) in [
        (Rtype::CAA, b"\x00\x05issue".to_vec()),
        (Rtype::DS, [vec![0, 1, 13, 2], vec![0xAB; 32]].concat()),
        (Rtype::SSHFP, [vec![4, 2], vec![0xAB; 32]].concat()),
        (Rtype::TLSA, [vec![3, 1, 1], vec![0xAB; 32]].concat()),
    ] {
        let mut record = update_record(rtype, Class::IN, 300, rdata.clone());
        let expected = record.to_record_value(&rdata).unwrap();
        let mut message = vec![0; 12];
        record.rdata_start = message.len();
        message.extend_from_slice(&rdata);
        message.extend_from_slice(b"following record or TSIG");
        assert_eq!(
            record.to_record_value(&message).unwrap(),
            expected,
            "{rtype}"
        );
    }
}

/// Verify that `to_record_value` follows compression pointer in name RDATA.
#[test]
fn to_record_value_follows_compression_pointer_in_name_rdata() {
    let mut message = vec![
        3, b'w', b'w', b'w', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let rdata_start = message.len();
    let pointer = [0xC0, 5]; // Points at the "example.com." bytes above
    message.extend_from_slice(&pointer);

    let record = UpdateRecord {
        name: "www.example.com.".to_string(),
        record_type: Rtype::CNAME,
        class: Class::IN,
        ttl: 300,
        rdata: pointer.to_vec(),
        rdata_start,
    };

    let (record_type, value, priority) = record.to_record_value(&message).unwrap();
    assert_eq!(record_type, RecordType::Cname);
    assert_eq!(value, "example.com.");
    assert_eq!(priority, None);
}

/// Verify that `to_record_value` rejects non backward compression pointers.
#[test]
fn to_record_value_rejects_non_backward_compression_pointers() {
    let forward = [
        0xC0, 0x02, // Pointer to the root label after this pointer
        0x00,
    ];
    let self_referential = [
        0xC0, 0x00, // Pointer to itself
    ];

    for message in [&forward[..], &self_referential[..]] {
        let record = update_record(Rtype::CNAME, Class::IN, 300, message[..2].to_vec());
        let err = record.to_record_value(message).unwrap_err();
        assert!(!err.to_string().is_empty());
    }
}

/// Verify that `to_record_value` rejects name RDATA with trailing bytes.
#[test]
fn to_record_value_rejects_name_rdata_with_trailing_bytes() {
    let message = [1, b'a', 0, 0];
    let record = update_record(Rtype::CNAME, Class::IN, 300, message.to_vec());
    let err = record.to_record_value(&message).unwrap_err();
    assert!(!err.to_string().is_empty());
}

/// Verify rejection of empty TXT RDATA, which lacks the character-string required by RFC 1035,
/// Section 3.3.14.
#[test]
fn to_record_value_rejects_empty_txt_rdata() {
    let record = update_record(Rtype::TXT, Class::IN, 300, Vec::new());
    let err = record.to_record_value(&[]).unwrap_err();
    assert!(!err.to_string().is_empty());
}

/// Preserve arbitrary TXT octets through UPDATE decoding.
#[test]
fn to_record_value_preserves_non_utf8_txt_character_strings() {
    let record = update_record(Rtype::TXT, Class::IN, 300, vec![1, 0xFF]);
    let (_, value, _) = record.to_record_value(&record.rdata).unwrap();
    assert_eq!(value, r#""\255""#);
}

/// Verify that `to_record_value` splits SRV priority into its own column.
#[test]
fn to_record_value_splits_srv_priority_into_its_own_column() {
    // priority 10, weight 20, port 5060, target sip.example.com.
    let mut rdata = vec![0, 10, 0, 20, 0x13, 0xC4];
    rdata.extend_from_slice(&[
        3, b's', b'i', b'p', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);
    let record = update_record(Rtype::SRV, Class::IN, 300, rdata.clone());

    let (record_type, value, priority) = record.to_record_value(&rdata).unwrap();

    assert_eq!(record_type, RecordType::Srv);
    // The wire encoder reads back this 3-field form with the priority column.
    assert_eq!(value, "20 5060 sip.example.com.");
    assert_eq!(priority, Some(10));
}

/// Build an nsupdate record with the requested wire fields.
fn update_record(record_type: Rtype, class: Class, ttl: u32, rdata: Vec<u8>) -> UpdateRecord {
    UpdateRecord {
        name: "www.example.com.".to_string(),
        record_type,
        class,
        ttl,
        rdata,
        rdata_start: 0,
    }
}

/// Verify empty ANY-class deletes and NONE-class deletes of specific RDATA
/// (RFC 2136, Section 2.5).
#[test]
fn update_shape_accepts_well_formed_deletes() {
    update_record(Rtype::A, Class::ANY, 0, Vec::new())
        .validate_update_shape()
        .unwrap();
    update_record(Rtype::A, Class::NONE, 0, vec![192, 0, 2, 1])
        .validate_update_shape()
        .unwrap();
}

/// Verify that each shape RFC 2136, Section 2.5 forbids is named.
#[test]
fn update_shape_reports_malformed_delete_fields() {
    for (record, expected) in [
        (
            update_record(Rtype::A, Class::ANY, 60, Vec::new()),
            ValidateUpdateShapeError::NonzeroTtl,
        ),
        (
            update_record(Rtype::A, Class::ANY, 0, vec![192, 0, 2, 1]),
            ValidateUpdateShapeError::AnyClassRdata,
        ),
        (
            update_record(Rtype::ANY, Class::NONE, 0, vec![192, 0, 2, 1]),
            ValidateUpdateShapeError::RecordType {
                record_type: Rtype::ANY,
            },
        ),
    ] {
        assert_eq!(record.validate_update_shape().unwrap_err(), expected);
    }
}

/// Verify that query/meta types are rejected in every update class, while
/// ANY remains the whole-name delete (RFC 2136, Section 3.4.1.2).
#[test]
fn update_shapes_distinguish_data_from_query_and_meta_types() {
    for class in [Class::IN, Class::ANY, Class::NONE] {
        for rtype in [
            Rtype::OPT,
            Rtype::TKEY,
            Rtype::TSIG,
            Rtype::IXFR,
            Rtype::AXFR,
            Rtype::MAILB,
            Rtype::MAILA,
            Rtype::ANY,
            Rtype::from_int(0),
            Rtype::from_int(128),
            Rtype::from_int(248),
            Rtype::from_int(65535),
        ] {
            let data = if class == Class::ANY { vec![] } else { vec![1] };
            let record = update_record(rtype, class, 0, data);
            let result = record.validate_update_shape();
            if class == Class::ANY && rtype == Rtype::ANY {
                assert!(result.is_ok());
            } else {
                assert_eq!(
                    result,
                    Err(ValidateUpdateShapeError::RecordType { record_type: rtype })
                );
            }
        }
        // A valid data type may be absent from the storage model; its
        // deletion still has a well-formed wire shape (RFC 3597, Section 2).
        for rtype in [Rtype::A, Rtype::SOA, Rtype::HINFO, Rtype::from_int(65280)] {
            let data = if class == Class::ANY { vec![] } else { vec![1] };
            update_record(rtype, class, 0, data)
                .validate_update_shape()
                .unwrap();
        }
    }
    assert_eq!(
        update_record(Rtype::A, Class::CH, 0, vec![192, 0, 2, 1]).validate_update_shape(),
        Err(ValidateUpdateShapeError::Class { class: Class::CH })
    );
    // TTL normalization belongs to additions, never to the delete shape.
    update_record(Rtype::A, Class::IN, u32::MAX, vec![192, 0, 2, 1])
        .validate_update_shape()
        .unwrap();
}

/// Verify that the OPT record is read as RFC 6891 asks: one is kept, two
/// are malformed, and a version above 0 is unsupported.
#[test]
fn parse_update_request_reads_the_opt_record() {
    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    append_opt_record(&mut message);
    assert_eq!(
        UpdateRequest::parse(&message).unwrap().edns,
        Edns::Present {
            udp_payload_size: 1232,
            version: 0,
            dnssec_ok: false,
        }
    );

    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 2);
    append_opt_record(&mut message);
    append_opt_record(&mut message);
    assert_eq!(
        UpdateRequest::parse(&message).unwrap().edns,
        Edns::Malformed
    );

    let mut message = minimal_update_with_ztype(6);
    set_arcount(&mut message, 1);
    // The TTL's second octet is the EDNS version.
    message.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(
        UpdateRequest::parse(&message).unwrap().edns,
        Edns::Present {
            udp_payload_size: 1232,
            version: 1,
            dnssec_ok: false,
        }
    );
}

/// Unsupported ordinary types cannot become stored update values.
#[test]
fn to_record_value_rejects_unsupported_ordinary_types() {
    for rtype in [Rtype::HINFO, Rtype::from_int(65280)] {
        let record = update_record(rtype, Class::IN, 300, vec![0, 0]);
        assert!(record.to_record_value(&record.rdata).is_err());
    }
}
