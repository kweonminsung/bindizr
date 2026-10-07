use std::{str::FromStr, sync::Arc};

use domain::{
    base::{Message, MessageBuilder, Name, iana::Rtype, opt::exterr::ExtendedError},
    rdata::tsig::Time48,
    tsig::{ClientSequence, Key},
};

use super::*;
use crate::{
    dns::tsig::verify_tsig_sequence,
    model::{record::RecordType, tsig_key::TsigAlgorithm},
};

/// A question for example.com and `qtype`, with one OPT record per entry
/// of `opt_versions`, each advertising 4096 octets.
fn question(qtype: Rtype, opt_versions: &[u8]) -> Vec<u8> {
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

/// The parsed form of a plain AXFR question.
fn axfr_query() -> ParsedQuery {
    ParsedQuery::parse(&question(Rtype::AXFR, &[])).unwrap()
}

/// Verify that `encode_tcp_message` rejects oversized payload.
#[test]
fn encode_tcp_message_rejects_oversized_payload() {
    let message = vec![0; DNS_TCP_MAX_SIZE + 1];

    assert!(encode_tcp_message(&message).is_err());
}

/// Verify that overflowing answers split into multiple frames.
#[test]
fn overflowing_answers_split_into_multiple_frames() {
    let mut builder = DnsMessageBuilder::new(&axfr_query(), Rtype::AXFR);
    let mut wire = Vec::new();

    for index in 0..4000 {
        let frame = builder
            .add_answer_or_overflow(|builder| {
                builder.add_text_rdata(
                    &format!("host-{}.example.com.", index),
                    3600,
                    &RecordType::A,
                    &format!("192.0.2.{}", index % 255),
                    None,
                )
            })
            .unwrap_or_else(|e| panic!("{}", e));
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

/// Verify that `truncated_response` echoes the question with tc set.
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
    let query = ParsedQuery::parse(&question.finish()).unwrap();

    let response = query.truncated_response();
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
    let query = question(Rtype::A, &[]);
    assert!(!is_response(&query));

    let parsed = ParsedQuery::parse(&query).expect("a question-only query parses");
    let reply = parsed.error_response(super::Rcode::REFUSED, None);
    assert!(is_response(&reply));
}

/// Build a signed AXFR query for `example.com.` and a `domain` client
/// sequence that verifies replies independently of the server under test.
fn signed_axfr_query(key: Arc<Key>) -> (Vec<u8>, ClientSequence<Arc<Key>>) {
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
    let client = ClientSequence::request(key, &mut additional, Time48::now()).unwrap();
    (additional.finish(), client)
}

/// Strip the 2-byte length prefix a TCP frame carries.
fn strip_frame_length(frame: Vec<u8>) -> Vec<u8> {
    frame[2..].to_vec()
}

/// Verify that every envelope of a signed transfer carries a verifiable mac.
#[test]
fn every_envelope_of_a_signed_transfer_carries_a_verifiable_mac() {
    let key = crate::dns::tsig::tests::test_key(TsigAlgorithm::HmacSha256)
        .to_domain_key()
        .unwrap();
    let (query, mut client) = signed_axfr_query(key.clone());

    let mut builder = DnsMessageBuilder::new(&axfr_query(), Rtype::AXFR)
        .sign_with(verify_tsig_sequence(&query, Some(key)).unwrap());

    // Two envelopes, so the second is checked against the MAC chain the first
    // started rather than against the request alone (RFC 8945, Section 5.3.1).
    let mut frames = Vec::new();
    for index in 0..4000 {
        let frame = builder
            .add_answer_or_overflow(|builder| {
                builder.add_text_rdata(
                    &format!("host-{}.example.com.", index),
                    3600,
                    &RecordType::A,
                    &format!("192.0.2.{}", index % 255),
                    None,
                )
            })
            .unwrap_or_else(|e| panic!("{}", e));
        if let Some(frame) = frame {
            frames.push(frame);
        }
    }
    frames.push(builder.take_frame().unwrap().unwrap());
    assert!(frames.len() >= 2, "expected a multi-message transfer");

    for frame in frames {
        let mut message = Message::from_octets(strip_frame_length(frame)).unwrap();
        client
            .answer(&mut message, Time48::now())
            .expect("envelope did not verify against the request's key");
    }
    client.done().expect("the sequence did not close cleanly");
}

/// Verify that a signed message reserves room for its TSIG record.
#[test]
fn a_signed_message_reserves_room_for_its_tsig_record() {
    let key = crate::dns::tsig::tests::test_key(TsigAlgorithm::HmacSha256)
        .to_domain_key()
        .unwrap();
    let (query, _) = signed_axfr_query(key.clone());
    let unsigned = DnsMessageBuilder::new(&axfr_query(), Rtype::AXFR);
    let signed = DnsMessageBuilder::new(&axfr_query(), Rtype::AXFR)
        .sign_with(verify_tsig_sequence(&query, Some(key)).unwrap());

    // Without the reservation an envelope could fill to the wire limit and
    // then overflow it once the TSIG record is appended.
    assert!(signed.message_len() > unsigned.message_len());
}

/// Verify the OPT handling of RFC 6891, Sections 6.1.1 and 6.1.3: echoed
/// with the extended error, FORMERR when doubled, BADVERS for a newer version.
#[test]
fn an_edns_query_is_answered_with_an_opt() {
    let parsed = ParsedQuery::parse(&question(Rtype::SOA, &[0])).unwrap();
    assert_eq!(
        parsed.edns,
        Edns::Present {
            udp_payload_size: 4096
        }
    );
    assert_eq!(parsed.udp_payload_limit(), 1232);
    assert!(parsed.edns_error_response().is_none());
    let reply = parsed.error_response(Rcode::REFUSED, Some(ExtendedErrorCode::PROHIBITED));
    let reply = Message::from_octets(reply.as_slice()).unwrap();
    let opt = reply.opt().expect("an EDNS query is answered with an OPT");
    assert_eq!(opt.version(), 0);
    assert_eq!(opt.udp_payload_size(), 1232);
    let ede = opt
        .opt()
        .iter::<ExtendedError<_>>()
        .next()
        .expect("the refusal names its reason")
        .unwrap();
    assert_eq!(ede.code(), ExtendedErrorCode::PROHIBITED);

    let doubled = ParsedQuery::parse(&question(Rtype::SOA, &[0, 0])).unwrap();
    assert_eq!(doubled.edns, Edns::Malformed);
    let reply = doubled.edns_error_response().unwrap();
    let reply = Message::from_octets(reply.as_slice()).unwrap();
    assert_eq!(reply.header().rcode(), Rcode::FORMERR);
    assert!(reply.opt().is_some());

    let newer = ParsedQuery::parse(&question(Rtype::SOA, &[1])).unwrap();
    assert_eq!(newer.edns, Edns::UnsupportedVersion(1));
    let reply = newer.edns_error_response().unwrap();
    let reply = Message::from_octets(reply.as_slice()).unwrap();
    let opt = reply.opt().unwrap();
    assert_eq!(opt.rcode(reply.header()), OptRcode::BADVERS);
    assert_eq!(opt.version(), 0);

    // Without EDNS the limit is RFC 1035's.
    assert_eq!(axfr_query().udp_payload_limit(), 512);
}

/// Verify that an answer over the UDP limit goes out truncated with its OPT
/// (RFC 6891, Section 6.2.5).
#[test]
fn an_answer_over_the_udp_limit_is_truncated() {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let parsed = ParsedQuery::parse(&question(Rtype::SOA, &[0])).unwrap();
    let mut builder = DnsMessageBuilder::new(&parsed, Rtype::SOA);
    for _ in 0..40 {
        builder
            .add_raw_rdata(
                qname.clone(),
                Rtype::TXT.to_int(),
                300,
                Rdata::new(vec![3, b'a', b'b', b'c']).unwrap(),
            )
            .unwrap();
    }

    let response = builder.build(512).unwrap();
    let response = Message::from_octets(response.as_slice()).unwrap();

    assert!(response.header().tc());
    assert_eq!(response.header_counts().ancount(), 0);
    assert!(response.opt().is_some());
}

/// Verify that a response echoes the class asked (RFC 5936, Section 2.2.2).
#[test]
fn a_response_echoes_the_question_class() {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(5);
    let mut question = builder.question();
    question.push((&qname, Rtype::SOA, Class::CH)).unwrap();
    let parsed = ParsedQuery::parse(&question.finish()).unwrap();
    assert_eq!(parsed.qclass, Class::CH);

    let reply = parsed.error_response(Rcode::NOTAUTH, None);
    let reply = Message::from_octets(reply.as_slice()).unwrap();
    assert_eq!(reply.first_question().unwrap().qclass(), Class::CH);
}
