use std::net::Ipv4Addr;

use domain::base::{Name, iana::Rtype};

use super::{
    DNS_TCP_MAX_SIZE, DnsMessageBuilder, XfrError, add_answer_and_flush_if_needed,
    encode_domain_name, encode_tcp_message, flush_message_if_not_empty, normalize_name,
};

#[test]
fn normalize_name_expands_relative_name() {
    assert_eq!(normalize_name("sub", "example.com"), "sub.example.com.");
}

#[test]
fn normalize_name_keeps_zone_qualified_name() {
    assert_eq!(
        normalize_name("www.example.com", "example.com."),
        "www.example.com."
    );
    assert_eq!(
        normalize_name("example.com", "example.com."),
        "example.com."
    );
}

#[test]
fn normalize_name_handles_fqdn_and_apex() {
    assert_eq!(normalize_name("sub.", "example.com."), "sub.");
    assert_eq!(normalize_name("@", "example.com."), "example.com.");
}

#[test]
fn encode_tcp_message_rejects_oversized_payload() {
    let message = vec![0; DNS_TCP_MAX_SIZE + 1];

    let err = encode_tcp_message(&message).unwrap_err();

    assert!(matches!(err, XfrError::ProtocolError(_)));
}

#[test]
fn encode_domain_name_respects_escaped_dots() {
    let mut encoded = Vec::new();

    encode_domain_name(r"admin\.dns.example.com.", &mut encoded).unwrap();

    assert_eq!(
        encoded,
        vec![
            9, b'a', b'd', b'm', b'i', b'n', b'.', b'd', b'n', b's', 7, b'e', b'x', b'a', b'm',
            b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ]
    );
}

#[tokio::test]
async fn chunked_tcp_writer_splits_large_answer_sets() {
    let mut qname = Vec::new();
    encode_domain_name("example.com.", &mut qname).unwrap();
    let qname = Name::from_octets(qname).unwrap();
    let mut builder = DnsMessageBuilder::new(1234, &qname, Rtype::AXFR);
    let mut writer = Vec::new();

    for index in 0..4000 {
        add_answer_and_flush_if_needed(&mut writer, &mut builder, |builder| {
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
