use std::str::FromStr;
use std::time::Duration;

use domain::base::Message;
use domain::base::opt::exterr::ExtendedError;
use domain::tsig::{ClientSequence, ClientTransaction};

use super::*;
use crate::dns;
use crate::dns::name::{OwnerName, ZoneName};
use crate::dns::query::TransferMessagePosition;
use crate::dns::record::{MAX_RECORD_RDATA, TxtRecordValue};
use crate::dns::tsig::TsigSigningKey;
use crate::dns::{CatalogZone, DNS_TCP_MAX_SIZE, Serial, SoaInterval, Ttl, query, tsig};
use crate::model::record::RecordType;
use crate::model::tsig_key::{TsigAlgorithm, TsigKey};

/// Verify that virtual catalog metadata retains its SOA, schema version and member wire records.
#[test]
fn catalog_response_preserves_metadata_and_member_records() {
    let catalog_zone = CatalogZone {
        name: ZoneName::parse("catalog.example").unwrap(),
        serial: Serial::from(42),
        default_ttl: Ttl::from_secs(3600),
        refresh: SoaInterval::from_secs(3600),
        retry: SoaInterval::from_secs(600),
        expire: SoaInterval::from_secs(86400),
        minimum_ttl: Ttl::from_secs(60),
    };
    let qname = catalog_zone.name.to_wire_name().unwrap();
    let mut question = build_response().question();
    question.push((qname.clone(), Rtype::AXFR)).unwrap();
    let query_data = question.finish().into_target();
    let query = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();
    let mut builder = DnsMessageBuilder::new(&query);
    builder.add_catalog_soa(&catalog_zone).unwrap();
    builder.add_catalog_ns(&catalog_zone).unwrap();
    builder.add_catalog_schema_version(&catalog_zone).unwrap();
    builder
        .add_catalog_ptr(&catalog_zone, &ZoneName::parse("member.example").unwrap())
        .unwrap();
    builder.add_catalog_soa(&catalog_zone).unwrap();
    let response = builder.build().unwrap();
    let records = query::extract_transfer_records(
        query.query_id,
        &qname,
        TransferMessagePosition::First,
        &response,
    )
    .unwrap();

    assert_eq!(records.len(), 5);
    assert!(records.iter().all(|record| record.ttl == 3600));
    assert_eq!(records[0], records[4]);
    // Both catalog names remain the protocol placeholder "invalid.".
    let mut soa = b"\x07invalid\0\x07invalid\0".to_vec();
    for field in [42u32, 3600, 600, 86400, 60] {
        soa.extend_from_slice(&field.to_be_bytes());
    }
    assert_eq!(records[0].rdata.as_bytes(), soa);
    assert_eq!(records[1].rdata.as_bytes(), b"\x07invalid\0");
    assert_eq!(records[2].rdata.as_bytes(), b"\x012");
    assert_eq!(
        dns::extract_member_zones(&records, &catalog_zone.name).unwrap(),
        vec![ZoneName::parse("member.example").unwrap()]
    );
}

/// Verify that signed replies with long keys fit the UDP limit without breaking their MAC.
#[test]
fn signed_udp_responses_preserve_macs_with_long_compressed_key_names() {
    let long_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let key = TsigKey {
        name: long_name.clone(),
        ..tsig::tests::test_key(TsigAlgorithm::HmacSha512)
    }
    .to_signing_key()
    .unwrap();

    for udp_size in [None, Some(512), Some(1232)] {
        let mut question = build_response().question();
        question
            .push((Name::<Vec<u8>>::from_str(&long_name).unwrap(), Rtype::SOA))
            .unwrap();
        let mut additional = question.additional();

        if let Some(size) = udp_size {
            additional
                .opt(|opt| {
                    opt.set_udp_payload_size(size);
                    Ok(())
                })
                .unwrap();
        }

        let client =
            ClientTransaction::request(key.clone(), &mut additional, Time48::now()).unwrap();
        let query_data = additional.finish().into_target();

        assert!(query_data.len() < 512);
        let query = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();
        let signer: TransferSigner = tsig::verify_tsig(&query_data, Some(key.clone()))
            .unwrap()
            .into();

        for rcode in [
            OptRcode::REFUSED,
            OptRcode::SERVFAIL,
            OptRcode::NOTAUTH,
            OptRcode::FORMERR,
        ] {
            let response = query
                .build_signed_error_response(
                    rcode,
                    Some(ExtendedErrorCode::PROHIBITED),
                    Some(&mut signer.clone()),
                )
                .unwrap();

            assert!(response.len() <= query.response_limit().max_len());
            assert_eq!(
                Message::from_octets(response.as_slice())
                    .unwrap()
                    .header()
                    .rcode(),
                rcode.rcode()
            );
            client
                .answer(
                    &mut Message::from_octets(response.clone()).unwrap(),
                    Time48::now(),
                )
                .unwrap();
            tsig::tests::assert_response_mac(&query_data, &response, TsigAlgorithm::HmacSha512);
        }

        let response = query
            .build_signed_truncated_response(Some(&mut signer.clone()))
            .unwrap();

        assert!(response.len() <= query.response_limit().max_len());
        assert!(
            Message::from_octets(response.as_slice())
                .unwrap()
                .header()
                .tc()
        );
        tsig::tests::assert_response_mac(&query_data, &response, TsigAlgorithm::HmacSha512);

        let mut builder = DnsMessageBuilder::new(&query).sign_with(signer);
        builder
            .add_raw_rdata(
                query.qname.clone(),
                Rtype::TXT.to_int(),
                3600,
                Rdata::new(vec![0; 1400]).unwrap(),
            )
            .unwrap();
        let response = builder.build().unwrap();
        let mut message = Message::from_octets(response.clone()).unwrap();

        assert!(message.header().tc());
        assert_eq!(message.header_counts().ancount(), 0);
        assert!(response.len() <= query.response_limit().max_len());
        client.answer(&mut message, Time48::now()).unwrap();
        tsig::tests::assert_response_mac(&query_data, &response, TsigAlgorithm::HmacSha512);
    }
}

/// Build a question for example.com and `qtype`, with one OPT record per entry
/// of `opt_versions`, each advertising 4096 octets.
fn build_question(qtype: Rtype, opt_versions: &[u8]) -> Vec<u8> {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(1234);
    let mut question = builder.question();
    question.push((&qname, qtype)).unwrap();
    let mut additional = question.additional();

    for version in opt_versions {
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(4096);
                opt.set_version(*version);
                Ok(())
            })
            .unwrap();
    }

    additional.finish()
}

/// Build the parsed form of a plain AXFR question.
fn axfr_query() -> ParsedQuery {
    ParsedQuery::parse(
        &build_question(Rtype::AXFR, &[]),
        Keepalive::IdleTimeout(Duration::ZERO),
    )
    .unwrap()
}

/// Verify that unreadable section boundaries cannot establish an OPT or a usable question.
#[test]
fn unreadable_query_bodies_receive_header_only_formerr() {
    for section in [4, 6, 8, 10] {
        let mut query_data = build_question(Rtype::SOA, &[]);
        query_data[section..section + 2].copy_from_slice(&2u16.to_be_bytes());

        for keepalive in [Keepalive::None, Keepalive::IdleTimeout(Duration::ZERO)] {
            let error = ParsedQuery::parse(&query_data, keepalive).unwrap_err();
            let response = error
                .query_metadata()
                .unwrap()
                .build_signed_error_response(OptRcode::FORMERR, None, None)
                .unwrap();
            let message = Message::from_octets(response.as_slice()).unwrap();

            assert_eq!(message.header().id(), 1234);
            assert!(message.header().qr());
            assert_eq!(message.header().rcode(), Rcode::FORMERR);
            assert_eq!(response.len(), 12);
            assert_eq!(message.header_counts().qdcount(), 0);
            assert_eq!(message.header_counts().arcount(), 0);
        }
    }
}

/// Verify that `encode_tcp_message` rejects oversized payload.
#[test]
fn encode_tcp_message_rejects_oversized_payload() {
    let message = vec![0; DNS_TCP_MAX_SIZE + 1];

    assert!(encode_tcp_message(&message).is_err());
}

/// Verify that overflowing answers split into multiple frames.
#[test]
fn encoding_splits_overflowing_answers_into_frames() {
    let mut builder = DnsMessageBuilder::new(&axfr_query());
    let mut wire = Vec::new();

    for index in 0..4000 {
        let frame = builder
            .add_answer_or_overflow(|builder| {
                builder.add_record_parts(
                    &OwnerName::from_row(&format!("host-{index}")),
                    &ZoneName::parse("example.com").unwrap(),
                    RecordType::A,
                    &format!("192.0.2.{}", index % 255),
                    Ttl::from_secs(3600),
                    None,
                )
            })
            .unwrap_or_else(|error| panic!("{error}"));

        if let Some(frame) = frame {
            wire.extend_from_slice(&frame);
        }
    }

    if let Some(frame) = builder.take_frame().unwrap() {
        wire.extend_from_slice(&frame);
    }

    let mut answer_count = 0usize;
    let mut frame_count = 0;
    let mut pos = 0;

    while pos < wire.len() {
        let len = usize::from(u16::from_be_bytes([wire[pos], wire[pos + 1]]));
        assert!(len <= DNS_TCP_MAX_SIZE);
        assert!(len > 0);
        answer_count += usize::from(u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]));
        frame_count += 1;
        pos += 2 + len;
    }

    assert_eq!(pos, wire.len());
    assert_eq!(answer_count, 4000);
    assert!(frame_count > 1);
}

/// Verify that `build_signed_truncated_response` echoes the question with tc set.
#[test]
fn truncated_response_echoes_the_question_with_tc_set() {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(4242);
    let mut question = builder.question();
    question
        .push((
            Name::<Vec<u8>>::from_str("example.com").unwrap(),
            Rtype::AXFR,
        ))
        .unwrap();
    let query = ParsedQuery::parse(&question.finish(), Keepalive::None).unwrap();

    let response = query.build_signed_truncated_response(None).unwrap();

    assert_eq!(&response[0..2], &4242u16.to_be_bytes());

    // QR, AA, and TC set; RCODE NOERROR; one question, no answers.
    assert_eq!(response[2], 0x86);
    assert_eq!(response[3] & 0x0f, 0);
    assert_eq!(&response[4..6], &1u16.to_be_bytes());
    assert_eq!(&response[6..8], &0u16.to_be_bytes());
}

/// Verify that `is_response` separates a reply from a query.
#[test]
fn is_response_separates_a_reply_from_a_query() {
    let query_data = build_question(Rtype::A, &[]);

    assert!(!is_response(&query_data));

    let query = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();
    let response = query
        .build_signed_error_response(Rcode::REFUSED.into(), None, None)
        .unwrap();

    assert!(is_response(&response));
}

/// Verify that QUERY's question limit is enforced and an unreadable body receives a header-only
/// error.
#[test]
fn multi_question_headers_receive_formerr_only_for_query() {
    for (opcode, count, expected) in [
        (Opcode::QUERY, 1u16, None),
        (Opcode::QUERY, 2, Some(OptRcode::FORMERR)),
        (Opcode::STATUS, 2, None),
    ] {
        let mut message = Message::from_octets(build_question(Rtype::SOA, &[])).unwrap();
        message.header_mut().set_opcode(opcode);
        let mut query_data = message.into_octets();
        query_data[4..6].copy_from_slice(&count.to_be_bytes());

        if count == 2 {
            query_data.extend_from_within(12..);
        }

        let query = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();

        assert_eq!(query.question_count, count);
        assert_eq!(query.format_error(), expected, "{opcode} QDCOUNT={count}");

        if let Some(rcode) = expected {
            let response = query
                .build_signed_error_response(rcode, None, None)
                .unwrap();
            let response = Message::from_octets(response).unwrap();

            assert_eq!(response.header().rcode(), Rcode::FORMERR);
            assert_eq!(response.header_counts().qdcount(), 1);
            assert_eq!(response.header_counts().ancount(), 0);
        }

        for body in [&[][..], &[0xc0, 0x0c][..]] {
            let mut unreadable = query_data[..12].to_vec();
            unreadable.extend_from_slice(body);
            let error = ParsedQuery::parse(&unreadable, Keepalive::None).unwrap_err();
            let response = Message::from_octets(
                error
                    .query_metadata()
                    .unwrap()
                    .build_signed_error_response(OptRcode::FORMERR, None, None)
                    .unwrap(),
            )
            .unwrap();

            assert_eq!(response.header().id(), 1234);
            assert_eq!(response.header().opcode(), opcode);
            assert_eq!(response.header().rcode(), Rcode::FORMERR);
            assert_eq!(response.header_counts().qdcount(), 0);
            assert_eq!(response.header_counts().ancount(), 0);
        }
    }
}

/// Verify that a QUERY without a question is answered FORMERR, not dropped (RFC 9619,
/// Section 4 leaves QDCOUNT = 0 to the server).
#[test]
fn question_less_queries_receive_formerr() {
    let mut query_data = build_question(Rtype::SOA, &[])[..12].to_vec();
    query_data[4..6].copy_from_slice(&0u16.to_be_bytes());
    let error = ParsedQuery::parse(&query_data, Keepalive::None).unwrap_err();
    let response = Message::from_octets(
        error
            .query_metadata()
            .unwrap()
            .build_signed_error_response(OptRcode::FORMERR, None, None)
            .unwrap(),
    )
    .unwrap();

    assert_eq!(response.header().id(), 1234);
    assert!(response.header().qr());
    assert_eq!(response.header().rcode(), Rcode::FORMERR);
    assert_eq!(response.header_counts().qdcount(), 0);

    // A header shorter than twelve octets names no query to answer.
    assert!(
        ParsedQuery::parse(&query_data[..11], Keepalive::None)
            .unwrap_err()
            .query_metadata()
            .is_none()
    );
}

/// Build a signed AXFR query for `example.com.` and a `domain` client
/// sequence that verifies replies independently of the server under test.
fn build_signed_axfr_query(
    key: TsigSigningKey,
    dnssec_ok: Option<bool>,
) -> (Vec<u8>, ClientSequence<TsigSigningKey>) {
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(1234);
    let mut question = builder.question();
    question
        .push((
            &Name::<Vec<u8>>::from_str("example.com.").unwrap(),
            Rtype::AXFR,
        ))
        .unwrap();

    let mut additional = question.additional();

    if let Some(dnssec_ok) = dnssec_ok {
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(4096);
                opt.set_dnssec_ok(dnssec_ok);
                Ok(())
            })
            .unwrap();
    }

    let client = ClientSequence::request(key, &mut additional, Time48::now()).unwrap();

    (additional.finish(), client)
}

/// Strip the 2-byte length prefix a TCP frame carries.
fn strip_frame_length(frame: Vec<u8>) -> Vec<u8> {
    frame[2..].to_vec()
}

/// Verify that every envelope of a signed transfer carries a verifiable mac.
#[test]
fn signed_transfer_authenticates_every_envelope() {
    let key = tsig::tests::test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let (query_data, mut client) = build_signed_axfr_query(key.clone(), Some(true));
    let query = ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(Duration::ZERO)).unwrap();

    let mut builder = DnsMessageBuilder::new(&query)
        .sign_with(tsig::verify_tsig(&query_data, Some(key)).unwrap().into());

    // Two envelopes, so the second is checked against the MAC chain the first
    // started rather than against the request alone (RFC 8945, Section 5.3.1).
    let mut frames = Vec::new();

    for index in 0..4000 {
        let frame = builder
            .add_answer_or_overflow(|builder| {
                builder.add_record_parts(
                    &OwnerName::from_row(&format!("host-{index}")),
                    &ZoneName::parse("example.com").unwrap(),
                    RecordType::A,
                    &format!("192.0.2.{}", index % 255),
                    Ttl::from_secs(3600),
                    None,
                )
            })
            .unwrap_or_else(|error| panic!("{error}"));

        if let Some(frame) = frame {
            frames.push(frame);
        }
    }

    frames.push(builder.take_frame().unwrap().unwrap());

    assert!(frames.len() >= 2, "expected a multi-message transfer");

    for frame in frames {
        let mut message = Message::from_octets(strip_frame_length(frame)).unwrap();
        assert!(message.opt().unwrap().dnssec_ok());
        client.answer(&mut message, Time48::now()).unwrap();
    }

    client.done().unwrap();
}

/// Verify that a signed message reserves room for its TSIG record.
#[test]
fn signed_message_reserves_space_for_tsig() {
    let key = tsig::tests::test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let (query_data, _) = build_signed_axfr_query(key.clone(), None);
    let unsigned = DnsMessageBuilder::new(&axfr_query());
    let signed = DnsMessageBuilder::new(&axfr_query())
        .sign_with(tsig::verify_tsig(&query_data, Some(key)).unwrap().into());

    // Without the reservation an envelope could fill to the wire limit and
    // then overflow it once the TSIG record is appended.
    assert!(signed.message_len() > unsigned.message_len());
}

/// Verify that every storable variable-size record fits a signed EDNS TCP envelope,
/// including maximal, unrelated question and key names.
#[test]
fn maximum_record_values_fit_signed_edns_transfer_frames() {
    let longest_name = |labels: [char; 4]| {
        labels
            .into_iter()
            .zip([63, 63, 63, 61])
            .map(|(ch, len)| ch.to_string().repeat(len))
            .collect::<Vec<_>>()
            .join(".")
    };
    let zone_name = ZoneName::parse(&longest_name(['a', 'b', 'c', 'd'])).unwrap();
    let qname = zone_name.to_wire_name().unwrap();
    let key = TsigKey {
        name: longest_name(['k', 'l', 'm', 'n']),
        ..tsig::tests::test_key(TsigAlgorithm::HmacSha512)
    }
    .to_signing_key()
    .unwrap();
    let mut remaining = MAX_RECORD_RDATA;
    let mut segments = Vec::new();

    while remaining > 0 {
        let len = (remaining - 1).min(255);
        segments.push(vec![b'x'; len]);
        remaining -= len + 1;
    }

    let values = [
        (
            RecordType::Txt,
            TxtRecordValue::from_octet_segments(segments.iter().map(Vec::as_slice))
                .unwrap()
                .to_presentation(),
        ),
        (
            RecordType::Caa,
            format!("0 issue \"{}\"", "x".repeat(MAX_RECORD_RDATA - 7)),
        ),
        (
            RecordType::Ds,
            format!("1 13 253 {}", "AB".repeat(MAX_RECORD_RDATA - 4)),
        ),
        (
            RecordType::Sshfp,
            format!("4 253 {}", "AB".repeat(MAX_RECORD_RDATA - 2)),
        ),
        (
            RecordType::Tlsa,
            format!("3 0 0 {}", "AB".repeat(MAX_RECORD_RDATA - 3)),
        ),
    ];

    for (record_type, value) in values {
        record_type.validate_value(&value, None).unwrap();
        let mut question = MessageBuilder::new_vec().question();
        question.push((&qname, Rtype::AXFR)).unwrap();
        let mut additional = question.additional();
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(1232);
                Ok(())
            })
            .unwrap();
        let mut client =
            ClientSequence::request(key.clone(), &mut additional, Time48::now()).unwrap();
        let query_data = additional.finish();
        let query =
            ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(Duration::from_secs(30)))
                .unwrap();
        let mut builder = DnsMessageBuilder::new(&query).sign_with(
            tsig::verify_tsig(&query_data, Some(key.clone()))
                .unwrap()
                .into(),
        );
        let mut frames = Vec::new();

        for _ in 0..2 {
            if let Some(frame) = builder
                .add_answer_or_overflow(|builder| {
                    builder.add_record_parts(
                        &OwnerName::apex(),
                        &zone_name,
                        record_type,
                        &value,
                        Ttl::from_secs(300),
                        None,
                    )
                })
                .unwrap_or_else(|error| panic!("{record_type}: {error}"))
            {
                frames.push(frame);
            }
        }

        frames.push(builder.take_frame().unwrap().unwrap());

        assert_eq!(frames.len(), 2);

        for frame in frames {
            assert_eq!(
                usize::from(u16::from_be_bytes([frame[0], frame[1]])),
                frame.len() - 2
            );
            let mut message = Message::from_octets(strip_frame_length(frame)).unwrap();

            assert!(message.as_slice().len() <= DNS_TCP_MAX_SIZE);
            assert!(message.opt().unwrap().opt().tcp_keepalive().is_some());
            let answer = message.answer().unwrap().next().unwrap().unwrap();

            assert_eq!(answer.rtype().to_int(), record_type.wire_type());
            assert_eq!(usize::from(answer.rdlen()), MAX_RECORD_RDATA);
            client.answer(&mut message, Time48::now()).unwrap();
        }

        client.done().unwrap();
    }
}

/// Verify that OPT follows RFC 6891, Sections 6.1.1 and 6.1.3: echoed
/// with the extended error, FORMERR when doubled, BADVERS for a newer version.
#[test]
fn edns_query_returns_opt() {
    let query = ParsedQuery::parse(&build_question(Rtype::SOA, &[0]), Keepalive::None).unwrap();

    assert_eq!(
        query.edns,
        Edns::Present {
            udp_payload_size: 4096,
            version: 0,
            dnssec_ok: false,
        }
    );
    assert_eq!(query.response_limit().max_len(), 1232);
    assert!(query.format_error().is_none());
    let response = query
        .build_signed_error_response(
            Rcode::REFUSED.into(),
            Some(ExtendedErrorCode::PROHIBITED),
            None,
        )
        .unwrap();
    let response = Message::from_octets(response.as_slice()).unwrap();
    let opt = response.opt().unwrap();

    assert_eq!(opt.version(), 0);
    assert_eq!(opt.udp_payload_size(), 1232);
    let ede = opt
        .opt()
        .iter::<ExtendedError<_>>()
        .next()
        .unwrap()
        .unwrap();

    assert_eq!(ede.code(), ExtendedErrorCode::PROHIBITED);

    let doubled =
        ParsedQuery::parse(&build_question(Rtype::SOA, &[0, 0]), Keepalive::None).unwrap();

    assert_eq!(doubled.edns, Edns::Malformed);
    let response = doubled
        .build_signed_error_response(doubled.format_error().unwrap(), None, None)
        .unwrap();
    let response = Message::from_octets(response.as_slice()).unwrap();

    assert_eq!(response.header().rcode(), Rcode::FORMERR);
    assert!(response.opt().is_some());

    let newer = ParsedQuery::parse(&build_question(Rtype::SOA, &[1]), Keepalive::None).unwrap();

    assert_eq!(
        newer.edns,
        Edns::Present {
            udp_payload_size: 4096,
            version: 1,
            dnssec_ok: false,
        }
    );
    let response = newer
        .build_signed_error_response(newer.format_error().unwrap(), None, None)
        .unwrap();
    let response = Message::from_octets(response.as_slice()).unwrap();
    let opt = response.opt().unwrap();

    assert_eq!(opt.rcode(response.header()), OptRcode::BADVERS);
    assert_eq!(opt.version(), 0);

    // Without EDNS the limit is RFC 1035's.
    assert_eq!(
        ParsedQuery::parse(&build_question(Rtype::AXFR, &[]), Keepalive::None)
            .unwrap()
            .response_limit()
            .max_len(),
        512
    );
}

/// Verify that error and truncated responses echo DO while clearing reserved EDNS flags.
#[test]
fn response_encoding_preserves_edns_dnssec_ok() {
    for version in [0, 1] {
        for flags in [0u16, 0x8000, 0x7fff, 0xffff] {
            let mut query_data = build_question(Rtype::SOA, &[version]);
            let offset = query_data.len() - 4;
            query_data[offset..offset + 2].copy_from_slice(&flags.to_be_bytes());
            let query = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();
            let rcode = query.format_error().unwrap_or(OptRcode::REFUSED);
            let responses = [
                query
                    .build_signed_error_response(rcode, Some(ExtendedErrorCode::PROHIBITED), None)
                    .unwrap(),
                query.build_signed_truncated_response(None).unwrap(),
            ];

            for response in responses {
                let response = Message::from_octets(response).unwrap();
                let opt = response.opt().unwrap();

                // RFC 6891, Section 6.1.4 leaves reserved flags clear.
                assert_eq!(
                    opt.as_record().ttl().as_secs() & 0xffff,
                    u32::from(flags & 0x8000)
                );
                assert_eq!(opt.version(), 0);
            }
        }
    }
}

/// Verify that an answer over the UDP limit goes out truncated with its OPT
/// (RFC 6891, Section 6.2.5).
#[test]
fn udp_response_truncates_answers_above_limit() {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let query = ParsedQuery::parse(&build_question(Rtype::SOA, &[0]), Keepalive::None).unwrap();
    let mut builder = DnsMessageBuilder::new(&query);

    for _ in 0..100 {
        builder
            .add_raw_rdata(
                qname.clone(),
                Rtype::TXT.to_int(),
                300,
                Rdata::new(vec![3, b'a', b'b', b'c']).unwrap(),
            )
            .unwrap();
    }

    let response = builder.build().unwrap();
    let response = Message::from_octets(response.as_slice()).unwrap();

    assert!(response.header().tc());
    assert_eq!(response.header_counts().ancount(), 0);
    assert!(response.opt().is_some());
}

/// Verify that a response echoes the class asked (RFC 5936, Section 2.2.2).
#[test]
fn response_encoding_preserves_question_class() {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(5);
    let mut question = builder.question();
    question.push((&qname, Rtype::SOA, Class::CH)).unwrap();
    let query = ParsedQuery::parse(&question.finish(), Keepalive::None).unwrap();

    assert_eq!(query.qclass, Class::CH);

    let response = query
        .build_signed_error_response(Rcode::NOTAUTH.into(), None, None)
        .unwrap();
    let response = Message::from_octets(response.as_slice()).unwrap();

    assert_eq!(response.first_question().unwrap().qclass(), Class::CH);
}

/// Verify that only TCP answers advertise edns-tcp-keepalive
/// (RFC 7828, Section 3.3.2).
#[test]
fn tcp_response_advertises_idle_timeout() {
    let tcp = ParsedQuery::parse(
        &build_question(Rtype::SOA, &[0]),
        Keepalive::IdleTimeout(Duration::from_secs(30)),
    )
    .unwrap();
    let response = tcp
        .build_signed_error_response(Rcode::REFUSED.into(), None, None)
        .unwrap();
    let message = Message::from_octets(response.as_slice()).unwrap();
    let keepalive = message.opt().unwrap().opt().tcp_keepalive().unwrap();

    assert_eq!(keepalive.timeout().map(u16::from), Some(300));

    let udp = ParsedQuery::parse(&build_question(Rtype::SOA, &[0]), Keepalive::None).unwrap();
    let response = udp
        .build_signed_error_response(Rcode::REFUSED.into(), None, None)
        .unwrap();
    let message = Message::from_octets(response.as_slice()).unwrap();

    assert!(message.opt().unwrap().opt().tcp_keepalive().is_none());
}

/// Verify that OPT is unique, root-owned, and confined to Additional (RFC 6891, Section 6.1.1).
#[test]
fn query_validation_rejects_invalid_opt_owner_and_section() {
    let plain = build_question(Rtype::SOA, &[]);
    let query_data = build_question(Rtype::SOA, &[0]);
    let start = plain.len();
    let mut named = query_data.clone();
    named.splice(start..=start, [1, b'x', 0]);

    assert_eq!(
        ParsedQuery::parse(&named, Keepalive::None)
            .unwrap()
            .format_error(),
        Some(OptRcode::FORMERR)
    );

    for count in [6, 8] {
        let mut misplaced = query_data.clone();
        misplaced[count..count + 2].copy_from_slice(&1u16.to_be_bytes());
        misplaced[10..12].fill(0);

        assert_eq!(
            ParsedQuery::parse(&misplaced, Keepalive::None)
                .unwrap()
                .format_error(),
            Some(OptRcode::FORMERR)
        );
        misplaced[10..12].copy_from_slice(&1u16.to_be_bytes());
        misplaced.extend_from_slice(&query_data[start..]);

        assert_eq!(
            ParsedQuery::parse(&misplaced, Keepalive::None)
                .unwrap()
                .format_error(),
            Some(OptRcode::FORMERR)
        );
    }
}

/// Verify that EDNS cannot lower the UDP floor or raise the server ceiling, and streams ignore it.
#[test]
fn response_limits_follow_transport_and_edns() {
    for (advertised, expected) in [
        (0, 512),
        (511, 512),
        (512, 512),
        (1232, 1232),
        (65535, 1232),
    ] {
        let limit = ResponseLimit::udp(advertised);

        assert!(limit.is_udp());
        assert_eq!(limit.max_len(), expected);
        assert!(limit.validate_len(expected).is_ok());
        assert!(
            matches!(limit.validate_len(expected + 1), Err(EncodeMessageError::TooLarge { len, max_len }) if len == expected + 1 && max_len == expected)
        );
        let (_, additional) = query::build_question(
            Opcode::QUERY,
            false,
            false,
            &Name::from_str("example.com").unwrap(),
            Rtype::SOA,
            Some(advertised),
        );
        let query_data = additional.finish();
        let udp = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();
        let stream =
            ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(Duration::ZERO)).unwrap();

        assert_eq!(udp.response_limit(), limit);
        assert_eq!(stream.response_limit(), ResponseLimit::STREAM);
    }

    assert!(ResponseLimit::STREAM.validate_len(65535).is_ok());
    assert!(ResponseLimit::STREAM.validate_len(65536).is_err());
}

/// Verify that a failed final size check does not consume the next MAC in a response chain.
#[test]
fn oversized_response_does_not_advance_the_signer() {
    let qname = Name::<Vec<u8>>::from_str(&format!(
        "{}.{}.{}.q",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63)
    ))
    .unwrap();
    let key = TsigKey {
        name: format!("{}.{}.{}.k", "d".repeat(63), "e".repeat(63), "f".repeat(63)),
        ..tsig::tests::test_key(TsigAlgorithm::HmacSha512)
    }
    .to_signing_key()
    .unwrap();
    let (_, mut additional) =
        query::build_question(Opcode::QUERY, false, false, &qname, Rtype::SOA, Some(512));
    let client = ClientTransaction::request(key.clone(), &mut additional, Time48::now()).unwrap();
    let query_data = additional.finish();
    let mut signer: TransferSigner = tsig::verify_tsig(&query_data, Some(key)).unwrap().into();
    let udp = ParsedQuery::parse(&query_data, Keepalive::None).unwrap();

    assert!(matches!(
        udp.build_signed_error_response(OptRcode::REFUSED, None, Some(&mut signer)),
        Err(EncodeMessageError::TooLarge {
            len: 520,
            max_len: 512
        })
    ));
    let stream = ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(Duration::ZERO)).unwrap();
    let response = stream
        .build_signed_error_response(OptRcode::REFUSED, None, Some(&mut signer))
        .unwrap();
    client
        .answer(&mut Message::from_octets(response).unwrap(), Time48::now())
        .unwrap();
}

/// Verify that a rejected TCP frame leaves the signer usable for the following error response.
#[test]
fn oversized_frame_does_not_advance_the_signer() {
    let key = tsig::tests::test_key(TsigAlgorithm::HmacSha256)
        .to_signing_key()
        .unwrap();
    let query = axfr_query();
    let (_, mut additional) =
        query::build_question(Opcode::QUERY, false, false, &query.qname, Rtype::AXFR, None);
    let client = ClientTransaction::request(key.clone(), &mut additional, Time48::now()).unwrap();
    let query_data = additional.finish();
    let query = ParsedQuery::parse(&query_data, Keepalive::IdleTimeout(Duration::ZERO)).unwrap();
    let signer = tsig::verify_tsig(&query_data, Some(key)).unwrap();
    let mut builder = DnsMessageBuilder::new(&query).sign_with(signer.into());

    // Bypass the chunking helper to exercise the final frame guard itself.
    for _ in 0..70 {
        builder
            .add_raw_rdata(
                query.qname.clone(),
                Rtype::TXT.to_int(),
                300,
                Rdata::new(vec![0; 1000]).unwrap(),
            )
            .unwrap();
    }

    assert!(matches!(
        builder.take_frame(),
        Err(EncodeMessageError::TooLarge { max_len: 65535, .. })
    ));
    let response = query
        .build_signed_error_response(OptRcode::SERVFAIL, None, builder.take_signer().as_mut())
        .unwrap();
    client
        .answer(&mut Message::from_octets(response).unwrap(), Time48::now())
        .unwrap();
}
