use std::sync::Arc;

use bindizr_core::config::Config;
use bindizr_core::metrics::Metrics;
use serde_json::json;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time;
use tokio::time::Duration;

use super::*;

/// Build isolated SQLite state with a bounded probe timeout and no workers.
async fn context() -> Arc<Context> {
    let config: Config = serde_json::from_value(json!({
        "database":{"sqlite":{"file_path":"sqlite::memory:"}},
        "dns":{"notify":{"timeout_secs":2}},
    }))
    .unwrap();
    let db = bindizr_db::Db::connect(&config.database).await.unwrap();
    let (jobs, _rx) = mpsc::unbounded_channel();
    let (period, _rx) = watch::channel(0);
    Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        jobs,
        period,
    ))
}

/// Serial ordering survives wraparound; half-range differences remain unordered.
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

/// Canceling the aggregate cancels its child exchange before any TCP fallback.
#[tokio::test]
async fn probe_secondaries_cancels_child_exchanges_with_the_request() {
    let cx = context().await;
    let (udp, tcp) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        match TcpListener::bind(udp.local_addr().unwrap()).await {
            Ok(tcp) => break (udp, tcp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("binding TCP listener failed: {error}"),
        }
    };
    secondary::create(
        &cx,
        &crate::authorization::Caller::socket(),
        &serde_json::from_value(json!({
            "name":"secondary", "address":udp.local_addr().unwrap().to_string(),
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let name = crate::zone::normalize_name("example.test").unwrap();
    let task_cx = cx.clone();
    let task = tokio::spawn(async move { probe_secondaries(&task_cx, &name, None).await });
    let mut query = [0u8; 4096];
    let (len, client) = time::timeout(Duration::from_secs(2), udp.recv_from(&mut query))
        .await
        .unwrap()
        .unwrap();

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    query[2] = 0x82; // QR and TC would otherwise start a TCP exchange.
    udp.send_to(&query[..len], client).await.unwrap();
    assert!(
        time::timeout(Duration::from_millis(150), tcp.accept())
            .await
            .is_err()
    );
}

/// Faster later targets do not reorder the secondary report.
#[tokio::test]
async fn probe_secondaries_preserves_order_when_later_targets_finish_first() {
    let cx = context().await;
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (name, socket) in [("a-first", &first), ("b-second", &second)] {
        secondary::create(
            &cx,
            &crate::authorization::Caller::socket(),
            &serde_json::from_value(json!({
                "name":name, "address":socket.local_addr().unwrap().to_string(),
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    }
    let name = crate::zone::normalize_name("example.test").unwrap();
    let task_cx = cx.clone();
    let task = tokio::spawn(async move { probe_secondaries(&task_cx, &name, None).await });
    let mut first_query = [0u8; 4096];
    let mut second_query = [0u8; 4096];
    let (first_len, first_client) =
        time::timeout(Duration::from_secs(2), first.recv_from(&mut first_query))
            .await
            .unwrap()
            .unwrap();
    let (second_len, second_client) =
        time::timeout(Duration::from_secs(2), second.recv_from(&mut second_query))
            .await
            .unwrap()
            .unwrap();

    // Refusals complete a probe without requiring an SOA fixture.
    second_query[2] = 0x84;
    second_query[3] = 5;
    second
        .send_to(&second_query[..second_len], second_client)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    first_query[2] = 0x84;
    first_query[3] = 5;
    first
        .send_to(&first_query[..first_len], first_client)
        .await
        .unwrap();

    let probes = task.await.unwrap().unwrap();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0].address, first.local_addr().unwrap().to_string());
    assert_eq!(probes[1].address, second.local_addr().unwrap().to_string());
    assert!(
        probes
            .iter()
            .all(|probe| probe.status == SecondaryStatus::Unreachable)
    );
}
