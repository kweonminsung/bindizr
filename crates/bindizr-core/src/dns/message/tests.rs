use std::str::FromStr;

use domain::base::{MessageBuilder, Name, iana::Rtype};

use super::{DNS_TCP_MAX_SIZE, DnsMessageBuilder, ParsedQuery, encode_tcp_message};
use crate::model::record::RecordType;

#[test]
fn encode_tcp_message_rejects_oversized_payload() {
    let message = vec![0; DNS_TCP_MAX_SIZE + 1];

    assert!(encode_tcp_message(&message).is_err());
}

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
