use std::str::FromStr;

use bindizr_core::dns::{message::Name, query::ParseResponseError};

use super::*;
use crate::dns_client::ds::tests::encode_name;

/// Build the test zone or its DNS name.
fn zone() -> Name<Vec<u8>> {
    Name::from_str("example.com").unwrap()
}

/// SOA probes retry truncated UDP answers over TCP.
#[tokio::test]
async fn soa_probe_returns_serial_after_tcp_fallback() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    let (tcp, udp) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()).await {
            break (tcp, udp);
        }
    };
    let address = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut query = [0; 4096];
        let (len, peer) = udp.recv_from(&mut query).await.unwrap();
        let id = u16::from_be_bytes([query[0], query[1]]);
        udp.send_to(
            &build_soa_response(id, 0x8600, "example.com", false, 0),
            peer,
        )
        .await
        .unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let tcp_len = stream.read_u16().await.unwrap();
        let mut request = vec![0; usize::from(tcp_len)];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, query[..len]);
        let response = build_soa_response(id, 0x8400, "example.com", true, 2026);
        stream.write_u16(response.len() as u16).await.unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let result = probe_address(&zone(), address, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(result, Serial::from(2026));
    server.await.unwrap();
}

/// Build an SOA response fixture with the requested header and serial.
fn build_soa_response(
    query_id: u16,
    flags: u16,
    qname: &str,
    with_answer: bool,
    serial: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&query_id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&(u16::from(with_answer)).to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    encode_name(qname, &mut buf);
    buf.extend_from_slice(&6u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());

    if with_answer {
        encode_name(qname, &mut buf);
        buf.extend_from_slice(&6u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&3600u32.to_be_bytes());

        let mut rdata = Vec::new();
        encode_name("ns1.example.com", &mut rdata);
        encode_name("admin.example.com", &mut rdata);
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&7200u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&604800u32.to_be_bytes());
        rdata.extend_from_slice(&3600u32.to_be_bytes());

        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
    }

    buf
}

/// Verify that `extract_soa_serial` reads the answer serial.
#[test]
fn extract_soa_serial_reads_the_answer_serial() {
    // 0x8400 = QR + AA, NOERROR.
    let response = build_soa_response(42, 0x8400, "example.com", true, 2026);
    assert_eq!(extract_soa_serial(42, &zone(), &response).unwrap(), 2026);
}

/// Verify that `extract_soa_serial` rejects id mismatch.
#[test]
fn extract_soa_serial_rejects_id_mismatch() {
    let response = build_soa_response(42, 0x8400, "example.com", true, 2026);
    assert!(
        extract_soa_serial(7, &zone(), &response)
            .unwrap_err()
            .to_string()
            .contains("ID mismatch")
    );
}

/// Verify that `extract_soa_serial` rejects error rcode.
#[test]
fn extract_soa_serial_rejects_error_rcode() {
    // RCODE 5 (REFUSED)
    let response = build_soa_response(42, 0x8405, "example.com", true, 2026);
    assert!(matches!(
        extract_soa_serial(42, &zone(), &response).unwrap_err(),
        ParseResponseError::Rcode(5)
    ));
}

/// Verify that `extract_soa_serial` rejects missing qr bit.
#[test]
fn extract_soa_serial_rejects_missing_qr_bit() {
    let response = build_soa_response(42, 0x0400, "example.com", true, 2026);
    assert!(
        extract_soa_serial(42, &zone(), &response)
            .unwrap_err()
            .to_string()
            .contains("QR bit")
    );
}

/// Verify that `extract_soa_serial` rejects truncated response.
#[test]
fn extract_soa_serial_rejects_truncated_response() {
    let response = build_soa_response(42, 0x8600, "example.com", true, 2026);
    assert!(matches!(
        extract_soa_serial(42, &zone(), &response).unwrap_err(),
        ParseResponseError::Truncated
    ));
}

/// Verify that `extract_soa_serial` rejects answer without SOA.
#[test]
fn extract_soa_serial_rejects_answer_without_soa() {
    let response = build_soa_response(42, 0x8400, "example.com", false, 0);
    assert!(matches!(
        extract_soa_serial(42, &zone(), &response).unwrap_err(),
        ParseResponseError::NoSoa
    ));
}

/// Verify that `extract_soa_serial` rejects a cache or another question.
#[test]
fn extract_soa_serial_rejects_a_cache_or_another_question() {
    // 0x8000 = QR without AA: a cache answered, not the secondary.
    let cached = build_soa_response(42, 0x8000, "example.com", true, 2026);
    assert!(matches!(
        extract_soa_serial(42, &zone(), &cached).unwrap_err(),
        ParseResponseError::NotAuthoritative
    ));
    let other = build_soa_response(42, 0x8400, "other.com", true, 2026);
    assert!(matches!(
        extract_soa_serial(42, &zone(), &other).unwrap_err(),
        ParseResponseError::OtherQuestion
    ));
}

/// Serial comparisons retain their direction across wraparound and leave half-range unordered.
#[test]
fn secondary_status_uses_rfc1982_order() {
    for (expected, visible, status) in [
        (0, u32::MAX, SecondaryStatus::Lagging),
        (u32::MAX, 0, SecondaryStatus::Ahead),
        (0, 0, SecondaryStatus::InSync),
        (0, 0x8000_0000, SecondaryStatus::Reachable),
    ] {
        assert_eq!(
            build_secondary_status(
                "server".into(),
                Some(Serial::from(expected)),
                Ok(Serial::from(visible))
            )
            .status,
            status
        );
    }
}

/// A malformed, unrelated or wrong-opcode datagram cannot end a live UDP probe.
#[tokio::test]
async fn udp_probe_discards_invalid_datagrams_without_resending() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut request = [0; 4096];
        let (_, peer) = socket.recv_from(&mut request).await.unwrap();
        let id = u16::from_be_bytes([request[0], request[1]]);
        for response in [
            vec![0],
            build_soa_response(id.wrapping_add(1), 0x8600, "example.com", true, 7),
            build_soa_response(id, 0xa400, "example.com", true, 7),
            build_soa_response(id, 0x8400, "other.example", true, 7),
            build_soa_response(id, 0x8400, "example.com", true, 99),
        ] {
            socket.send_to(&response, peer).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut request))
                .await
                .is_err()
        );
    });
    assert_eq!(
        probe_address(&zone(), address, Duration::from_secs(1))
            .await
            .unwrap(),
        Serial::from(99)
    );
    server.await.unwrap();
}
