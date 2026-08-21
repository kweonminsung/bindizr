use std::str::FromStr;

use bindizr_core::model::record::RecordType;
use domain::base::{Name, iana::Rtype};

use super::{DNS_TCP_MAX_SIZE, DnsMessageBuilder, XfrError, encode_tcp_message, parse_name};

#[test]
fn encode_tcp_message_rejects_oversized_payload() {
    let message = vec![0; DNS_TCP_MAX_SIZE + 1];

    let err = encode_tcp_message(&message).unwrap_err();

    assert!(matches!(err, XfrError::ProtocolError(_)));
}

#[tokio::test]
async fn chunked_tcp_writer_splits_large_answer_sets() {
    let qname = Name::<Vec<u8>>::from_str("example.com.").unwrap();
    let mut builder = DnsMessageBuilder::new(1234, &qname, Rtype::AXFR);
    let mut writer = Vec::new();
    let mut sent = 0usize;

    for index in 0..4000 {
        builder
            .add_answer_and_flush_if_needed(&mut writer, &mut sent, |builder| {
                builder.add_text_rdata(
                    &format!("host-{}.example.com.", index),
                    3600,
                    &RecordType::A,
                    &format!("192.0.2.{}", index % 255),
                    None,
                )
            })
            .await
            .unwrap();
    }
    builder.flush_if_not_empty(&mut writer).await.unwrap();

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
