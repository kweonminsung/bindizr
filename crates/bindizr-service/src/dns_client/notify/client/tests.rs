use std::collections::HashSet;
use std::io;
use std::str::FromStr;

use bindizr_core::dns::message::{Keepalive, ParsedQuery, Rcode};
use bindizr_core::dns::query;
use thiserror::Error;
use tokio::time;

use super::*;

/// Verify that every affected request retains the same socket error, including OS codes
/// and custom causes.
#[tokio::test]
async fn shared_socket_failure_preserves_original_io_error() {
    use std::error::Error;

    #[derive(Debug, Error)]
    #[error("socket operation failed")]
    struct SocketCause;

    for original in [
        io::Error::from_raw_os_error(54),
        io::Error::other(SocketCause),
    ] {
        let code = original.raw_os_error();
        let message = original.to_string();
        let qname = Name::from_str("example.com").unwrap();
        let mut requests = HashMap::new();
        let mut replies = Vec::new();

        for id in 0..2 {
            let (reply, response) = oneshot::channel();
            let (_, builder) = query::build_notify_query(&qname, None);
            requests.insert(
                id,
                PendingNotify {
                    request: builder.finish(),
                    limit: ResponseLimit::UDP,
                    verifier: None,
                    timeout: Duration::from_secs(1),
                    retries_left: 0,
                    deadline: Instant::now(),
                    waiting: true,
                    sent: true,
                    qname: qname.clone(),
                    reply,
                },
            );
            replies.push(response);
        }

        fail_requests(&mut requests, original);

        assert!(requests.is_empty());
        let mut shared = Vec::new();

        for reply in replies {
            let error = reply.await.unwrap().unwrap_err();

            assert_eq!(error.to_string(), message);
            assert!(error.source().is_some());
            let SendNotifyError::Io(source) = error else {
                panic!("socket failure changed classification");
            };

            assert_eq!(source.raw_os_error(), code);

            if code.is_none() {
                assert!(source.get_ref().unwrap().is::<SocketCause>());
            }

            shared.push(source);
        }

        assert!(Arc::ptr_eq(&shared[0], &shared[1]));
    }
}

/// Verify that exhausting an ID space rotates the socket instead of reusing a live or
/// retired ID.
#[tokio::test]
async fn id_exhaustion_rotates_the_socket() {
    let client = NotifyClient::default();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    let (first, id) = client.reserve(addr).await.unwrap();
    let mut ids = HashSet::from([id]);

    for _ in 0..u16::MAX {
        let (target, id) = client.reserve(addr).await.unwrap();
        assert!(Arc::ptr_eq(&target, &first));
        assert!(ids.insert(id));
    }

    assert_eq!(ids.len(), 65536);

    let (next, _) = client.reserve(addr).await.unwrap();

    assert!(!Arc::ptr_eq(&next, &first));
}

/// Verify that peer filtering and retired IDs prevent old or spoofed ACKs ending a later
/// event.
#[tokio::test]
async fn wrong_peer_and_retired_ack_cannot_complete_a_new_transaction() {
    let client = NotifyClient::default();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let qname = Name::from_str("example.com").unwrap();

    let mut first = client
        .send(&qname, addr, Duration::from_secs(1), 0, None)
        .await
        .unwrap();

    let mut buffer = [0; 4096];

    let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
    let query = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
    let old_ack = query
        .build_signed_error_response(Rcode::NOERROR.into(), None, None)
        .unwrap();

    let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    intruder.send_to(&old_ack, peer).await.unwrap();
    time::sleep(Duration::from_millis(10)).await;

    assert!(matches!(
        first.response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    // Hold the socket across completion to exercise retired IDs on the same peer port.
    let held = first.target.clone();

    socket.send_to(&old_ack, peer).await.unwrap();
    first.wait().await.unwrap();
    let mut second = client
        .send(&qname, addr, Duration::from_secs(1), 0, None)
        .await
        .unwrap();
    let (len, second_peer) = socket.recv_from(&mut buffer).await.unwrap();

    assert_eq!(peer, second_peer);
    let next = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();

    assert_ne!(query.query_id, next.query_id);

    socket.send_to(&old_ack, peer).await.unwrap();
    time::sleep(Duration::from_millis(10)).await;

    assert!(matches!(
        second.response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    socket
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

/// Verify that an oversized matching ACK, including a truncated prefix, cannot end a
/// transaction.
#[tokio::test]
async fn oversized_ack_is_ignored_until_a_bounded_ack_arrives() {
    for size in [513, 4096] {
        let client = NotifyClient::default();

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let qname = Name::from_str("example.com").unwrap();

        let mut handle = client
            .send(
                &qname,
                socket.local_addr().unwrap(),
                Duration::from_secs(1),
                0,
                None,
            )
            .await
            .unwrap();

        let mut buffer = [0; 1232];

        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
        let ack = query
            .build_signed_error_response(Rcode::NOERROR.into(), None, None)
            .unwrap();
        let mut oversized = ack.clone();
        oversized.resize(size, 0);

        socket.send_to(&oversized, peer).await.unwrap();
        time::sleep(Duration::from_millis(20)).await;

        assert!(matches!(
            handle.response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        socket.send_to(&ack, peer).await.unwrap();
        handle.wait().await.unwrap();
    }
}
