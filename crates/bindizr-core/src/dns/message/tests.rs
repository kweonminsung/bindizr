use std::{str::FromStr, sync::Arc};

use domain::{
    base::{Message, MessageBuilder, Name, iana::Rtype},
    rdata::tsig::Time48,
    tsig::{ClientSequence, Key},
};

use super::{DNS_TCP_MAX_SIZE, DnsMessageBuilder, ParsedQuery, encode_tcp_message, is_response};
use crate::{
    dns::tsig::{to_domain_key, verify_tsig_sequence},
    model::{record::RecordType, tsig_key::TsigAlgorithm},
};

/// Verify that `encode_tcp_message` rejects oversized payload.
#[test]
fn encode_tcp_message_rejects_oversized_payload() {
    let message = vec![0; DNS_TCP_MAX_SIZE + 1];

    assert!(encode_tcp_message(&message).is_err());
}

/// Verify that overflowing answers split into multiple frames.
#[test]
fn overflowing_answers_split_into_multiple_frames() {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let mut builder = DnsMessageBuilder::new(1234, &qname, Rtype::AXFR);
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
            .unwrap_or_else(|e| panic!("{}", e.message));
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
        let len = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
        assert!(len <= DNS_TCP_MAX_SIZE);
        assert!(len > 0);
        answer_count += u16::from_be_bytes([wire[pos + 8], wire[pos + 9]]) as usize;
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
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();

    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(1234);
    let mut question = builder.question();
    question.push((&qname, Rtype::A)).unwrap();
    let query = question.finish();
    assert!(!is_response(&query));

    let parsed = ParsedQuery::parse(&query).expect("a question-only query parses");
    let reply = parsed.error_response(super::Rcode::REFUSED);
    assert!(is_response(&reply));
}

/// A signed AXFR query for `example.com.`, and the client sequence that
/// verifies what answers it — `domain`'s own client, so the check is
/// independent of the server code under test.
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
fn frame_message(frame: Vec<u8>) -> Vec<u8> {
    frame[2..].to_vec()
}

/// Verify that every envelope of a signed transfer carries a verifiable mac.
#[test]
fn every_envelope_of_a_signed_transfer_carries_a_verifiable_mac() {
    let key = to_domain_key(&crate::dns::tsig::tests::test_key(
        TsigAlgorithm::HmacSha256,
    ))
    .unwrap();
    let (query, mut client) = signed_axfr_query(key.clone());

    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let mut builder = DnsMessageBuilder::new(1234, &qname, Rtype::AXFR)
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
            .unwrap_or_else(|e| panic!("{}", e.message));
        if let Some(frame) = frame {
            frames.push(frame);
        }
    }
    frames.push(builder.take_frame().unwrap().unwrap());
    assert!(frames.len() >= 2, "expected a multi-message transfer");

    for frame in frames {
        let mut message = Message::from_octets(frame_message(frame)).unwrap();
        client
            .answer(&mut message, Time48::now())
            .expect("envelope did not verify against the request's key");
    }
    client.done().expect("the sequence did not close cleanly");
}

/// Verify that a signed message reserves room for its TSIG record.
#[test]
fn a_signed_message_reserves_room_for_its_tsig_record() {
    let key = to_domain_key(&crate::dns::tsig::tests::test_key(
        TsigAlgorithm::HmacSha256,
    ))
    .unwrap();
    let (query, _) = signed_axfr_query(key.clone());
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();

    let unsigned = DnsMessageBuilder::new(1234, &qname, Rtype::AXFR);
    let signed = DnsMessageBuilder::new(1234, &qname, Rtype::AXFR)
        .sign_with(verify_tsig_sequence(&query, Some(key)).unwrap());

    // Without the reservation an envelope could fill to the wire limit and
    // then overflow it once the TSIG record is appended.
    assert!(signed.message_len() > unsigned.message_len());
}
