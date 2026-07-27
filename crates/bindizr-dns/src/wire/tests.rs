use std::{net::Ipv4Addr, str::FromStr};

use domain::base::{Name, iana::Rtype};

use super::{
    DNS_TCP_MAX_SIZE, DnsMessageBuilder, XfrError, add_answer_and_flush_if_needed,
    encode_tcp_message, flush_message_if_not_empty, parse_name,
};

#[test]
fn encode_tcp_message_rejects_oversized_payload() {
    let message = vec![0; DNS_TCP_MAX_SIZE + 1];

    let err = encode_tcp_message(&message).unwrap_err();

    assert!(matches!(err, XfrError::ProtocolError(_)));
}

#[test]
fn parse_name_respects_escaped_dots() {
    let name = parse_name(r"admin\.dns.example.com.").unwrap();

    assert_eq!(
        name.as_slice(),
        [
            9, b'a', b'd', b'm', b'i', b'n', b'.', b'd', b'n', b's', 7, b'e', b'x', b'a', b'm',
            b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ]
    );
}

#[tokio::test]
async fn chunked_tcp_writer_splits_large_answer_sets() {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let mut builder = DnsMessageBuilder::new(1234, &qname, Rtype::AXFR);
    let mut writer = Vec::new();
    let mut sent = 0usize;

    for index in 0..4000 {
        add_answer_and_flush_if_needed(&mut writer, &mut builder, &mut sent, |builder| {
            builder.add_a_record(
                &format!("host-{}.example.com.", index),
                3600,
                Ipv4Addr::new(192, 0, 2, (index % 255) as u8),
            )
        })
        .await
        .unwrap();
    }
    flush_message_if_not_empty(&mut writer, &mut builder)
        .await
        .unwrap();

    let mut answer_count = 0usize;
    let mut frame_count = 0;
    let mut pos = 0;
    while pos < writer.len() {
        let len = u16::from_be_bytes([writer[pos], writer[pos + 1]]) as usize;
        assert!(len <= DNS_TCP_MAX_SIZE);
        assert!(len > 0);
        answer_count += u16::from_be_bytes([writer[pos + 8], writer[pos + 9]]) as usize;
        frame_count += 1;
        pos += 2 + len;
    }

    assert_eq!(pos, writer.len());
    assert_eq!(answer_count, 4000);
    assert!(frame_count > 1);
}
