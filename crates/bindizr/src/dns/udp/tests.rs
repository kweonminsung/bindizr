use std::time::Duration;

use tokio::{task::JoinSet, time::timeout};

use super::*;

/// Connected clients accept replies only from the address and port they queried.
async fn exchange(bind_ip: IpAddr, destinations: &[IpAddr]) {
    let socket = tokio::net::UdpSocket::bind((bind_ip, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Arc::new(UdpSocket::new(socket).unwrap());
    let mut clients = Vec::new();
    for (index, destination) in destinations.iter().enumerate() {
        let client_ip = if destination.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        let client = tokio::net::UdpSocket::bind((client_ip, 0)).await.unwrap();
        client.connect((*destination, port)).await.unwrap();
        client.send(&[u8::try_from(index).unwrap()]).await.unwrap();
        clients.push(client);
    }

    let mut received = Vec::new();
    for _ in destinations {
        let mut buf = [0; 128];
        let (len, target) = timeout(Duration::from_secs(2), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let index = usize::from(buf[0]);
        assert_eq!(target.local_ip.to_canonical(), destinations[index]);
        assert_eq!(
            target.client_addr.ip().to_canonical(),
            clients[index].local_addr().unwrap().ip()
        );
        received.push((target, buf[..len].to_vec()));
    }

    // Responses retain their own destination even after other packets arrive.
    let mut replies = JoinSet::new();
    for (target, data) in received.into_iter().rev() {
        let server = server.clone();
        replies.spawn(async move { server.send_to(&data, target).await.unwrap() });
    }
    while let Some(result) = replies.join_next().await {
        assert_eq!(result.unwrap(), 1);
    }
    for (index, client) in clients.into_iter().enumerate() {
        let mut buf = [0; 128];
        let (len, peer) = timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer, SocketAddr::new(destinations[index], port));
        assert_eq!(&buf[..len], &[u8::try_from(index).unwrap()]);
    }
}

/// Specific IPv4 and IPv6 listeners preserve their configured address.
#[tokio::test]
async fn specific_addresses_reply_from_the_bound_address() {
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        exchange(ip, &[ip]).await;
    }
}

/// IPv4 wildcard listeners reply using the packet's destination address.
#[tokio::test]
async fn ipv4_wildcard_preserves_destination() {
    exchange(Ipv4Addr::UNSPECIFIED.into(), &[Ipv4Addr::LOCALHOST.into()]).await;
}

/// IPv6 wildcard listeners also handle IPv4-mapped requests on the same socket.
#[tokio::test]
async fn ipv6_wildcard_preserves_both_address_families() {
    exchange(
        Ipv6Addr::UNSPECIFIED.into(),
        &[
            Ipv6Addr::LOCALHOST.into(),
            Ipv4Addr::LOCALHOST.into(),
            Ipv6Addr::LOCALHOST.into(),
        ],
    )
    .await;
}

/// Linux routes distinct 127/8 destinations locally without interface aliases.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn replies_do_not_mix_up_local_destinations() {
    let destinations = [
        Ipv4Addr::new(127, 0, 0, 2).into(),
        Ipv4Addr::LOCALHOST.into(),
        Ipv4Addr::new(127, 0, 0, 3).into(),
        Ipv4Addr::new(127, 0, 0, 2).into(),
    ];
    exchange(Ipv4Addr::UNSPECIFIED.into(), &destinations).await;
    exchange(Ipv6Addr::UNSPECIFIED.into(), &destinations).await;
}

/// A truncated datagram is rejected before it can be parsed or answered.
#[tokio::test]
async fn truncated_datagram_is_rejected() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let server = UdpSocket::new(socket).unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&[0; 32], addr).await.unwrap();
    let result = timeout(Duration::from_secs(2), server.recv_from(&mut [0; 4]))
        .await
        .unwrap();
    assert!(matches!(result, Err(UdpError::Truncated)));
}

/// Missing packet information never falls back to an OS-selected source address.
#[tokio::test]
async fn missing_destination_is_rejected() {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = UdpSocket { socket };
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&[0; 32], (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let result = timeout(Duration::from_secs(2), server.recv_from(&mut [0; 128]))
        .await
        .unwrap();
    assert!(matches!(result, Err(UdpError::MissingDestination)));
}
