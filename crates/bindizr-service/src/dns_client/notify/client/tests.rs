use std::{collections::HashSet, str::FromStr};

use bindizr_core::dns::message::{Keepalive, ParsedQuery, Rcode};

use super::*;

/// Exhausting an ID space rotates the socket instead of reusing a live or retired ID.
#[tokio::test]
async fn id_exhaustion_rotates_the_socket() {
    let client = NotifyClient::default();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let (first, id) = client.reserve(address).await.unwrap();
    let mut ids = HashSet::from([id]);
    for _ in 0..u16::MAX {
        let (target, id) = client.reserve(address).await.unwrap();
        assert!(Arc::ptr_eq(&target, &first));
        assert!(ids.insert(id));
    }
    assert_eq!(ids.len(), 65536);
    let (next, _) = client.reserve(address).await.unwrap();
    assert!(!Arc::ptr_eq(&next, &first));
}

/// Peer filtering and retired IDs prevent old or spoofed ACKs ending a later event.
#[tokio::test]
async fn wrong_peer_and_retired_ack_cannot_complete_a_new_transaction() {
    let client = NotifyClient::default();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let name = Name::from_str("example.com").unwrap();
    let mut first = client
        .start(&name, address, Duration::from_secs(1), 0, None)
        .await
        .unwrap();
    let mut buffer = [0; 4096];
    let (len, peer) = server.recv_from(&mut buffer).await.unwrap();
    let query = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
    let old_ack = query
        .build_signed_error_response(Rcode::NOERROR.into(), None, None)
        .unwrap();
    let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    intruder.send_to(&old_ack, peer).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(matches!(
        first.response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    // Hold the socket across completion to exercise retired IDs on the same peer port.
    let held = first.target.clone();
    server.send_to(&old_ack, peer).await.unwrap();
    first.wait().await.unwrap();
    let mut second = client
        .start(&name, address, Duration::from_secs(1), 0, None)
        .await
        .unwrap();
    let (len, second_peer) = server.recv_from(&mut buffer).await.unwrap();
    assert_eq!(peer, second_peer);
    let next = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
    assert_ne!(query.query_id, next.query_id);
    server.send_to(&old_ack, peer).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(matches!(
        second.response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    server
        .send_to(
            &next
                .build_signed_error_response(Rcode::NOERROR.into(), None, None)
                .unwrap(),
            peer,
        )
        .await
        .unwrap();
    second.wait().await.unwrap();
    drop(held);
}

/// An oversized matching ACK, including a truncated prefix, cannot end a transaction.
#[tokio::test]
async fn oversized_ack_is_ignored_until_a_bounded_ack_arrives() {
    for size in [513, 4096] {
        let client = NotifyClient::default();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let name = Name::from_str("example.com").unwrap();
        let mut exchange = client
            .start(
                &name,
                server.local_addr().unwrap(),
                Duration::from_secs(1),
                0,
                None,
            )
            .await
            .unwrap();
        let mut buffer = [0; 1232];
        let (len, peer) = server.recv_from(&mut buffer).await.unwrap();
        let query = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
        let ack = query
            .build_signed_error_response(Rcode::NOERROR.into(), None, None)
            .unwrap();
        let mut oversized = ack.clone();
        oversized.resize(size, 0);
        server.send_to(&oversized, peer).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(matches!(
            exchange.response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        server.send_to(&ack, peer).await.unwrap();
        exchange.wait().await.unwrap();
    }
}
