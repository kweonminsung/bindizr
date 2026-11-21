use std::sync::Arc;
use std::time::Duration;
use std::{io, ptr};

use bindizr_core::config::Config;
use bindizr_core::dns::message::{Keepalive, OptRcode, ParsedQuery};
use bindizr_core::metrics::Metrics;
use bindizr_core::model::tsig_key::TsigKeyId;
use bindizr_db::Db;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time;

use super::*;
use crate::authorization::Caller;
use crate::dns_client::ResolveAddressError;
use crate::notify;
use crate::types::{CreateSecondaryRequest, UpdateSecondaryRequest};

/// Build isolated SQLite state with a bounded probe timeout and no workers.
async fn context() -> Arc<Context> {
    let mut config: Config = serde_json::from_str("{}").unwrap();
    config.database.sqlite.file_path = "sqlite::memory:".to_string();
    config.dns.notify.timeout_secs = 2;

    let db = Db::connect(&config.database).await.unwrap();
    Arc::new(Context::new(
        config,
        String::new(),
        db,
        Metrics::new().unwrap(),
        mpsc::unbounded_channel().0,
        mpsc::channel(1).0,
        watch::channel(0).0,
    ))
}

/// Verify that serial ordering survives wraparound and that half-range differences remain
/// unordered.
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
                "server".to_string(),
                Some(Serial::from(expected)),
                Ok(Serial::from(visible))
            )
            .status,
            status
        );
    }
}

/// Verify that canceling the aggregate cancels its child exchange before any TCP fallback.
#[tokio::test]
async fn probe_secondaries_cancels_child_exchanges_with_the_request() {
    let cx = context().await;
    let (socket, listener) = loop {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        match TcpListener::bind(socket.local_addr().unwrap()).await {
            Ok(listener) => break (socket, listener),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("binding TCP listener failed: {error}"),
        }
    };
    secondary::create(
        &cx,
        &Caller::socket(),
        &CreateSecondaryRequest {
            name: "secondary".to_string(),
            address: socket.local_addr().unwrap().to_string(),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();
    let zone_name = ZoneName::parse("example.test").unwrap();
    let task_cx = cx.clone();
    let task = tokio::spawn(async move { probe_secondaries(&task_cx, &zone_name, None).await });
    let mut buffer = [0; 4096];
    let (len, peer) = time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    buffer[2] = 0x82; // QR and TC would otherwise start a TCP exchange.
    socket.send_to(&buffer[..len], peer).await.unwrap();
    assert!(
        time::timeout(Duration::from_millis(150), listener.accept())
            .await
            .is_err()
    );
}

/// Verify that faster later targets do not reorder the secondary report.
#[tokio::test]
async fn probe_secondaries_preserves_order_when_later_targets_finish_first() {
    let cx = context().await;
    let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for (name, socket) in [("a-first", &first_socket), ("b-second", &second_socket)] {
        secondary::create(
            &cx,
            &Caller::socket(),
            &CreateSecondaryRequest {
                name: name.to_string(),
                address: socket.local_addr().unwrap().to_string(),
                notify_key_name: None,
            },
        )
        .await
        .unwrap();
    }
    let zone_name = ZoneName::parse("example.test").unwrap();
    let task_cx = cx.clone();
    let task = tokio::spawn(async move { probe_secondaries(&task_cx, &zone_name, None).await });
    let mut first_buffer = [0; 4096];
    let mut second_buffer = [0; 4096];
    let (first_len, first_peer) = time::timeout(
        Duration::from_secs(2),
        first_socket.recv_from(&mut first_buffer),
    )
    .await
    .unwrap()
    .unwrap();
    let (second_len, second_peer) = time::timeout(
        Duration::from_secs(2),
        second_socket.recv_from(&mut second_buffer),
    )
    .await
    .unwrap()
    .unwrap();

    // Refusals complete a probe without requiring an SOA fixture.
    second_buffer[2] = 0x84;
    second_buffer[3] = 5;
    second_socket
        .send_to(&second_buffer[..second_len], second_peer)
        .await
        .unwrap();
    time::sleep(Duration::from_millis(20)).await;
    first_buffer[2] = 0x84;
    first_buffer[3] = 5;
    first_socket
        .send_to(&first_buffer[..first_len], first_peer)
        .await
        .unwrap();

    let statuses = task.await.unwrap().unwrap();
    assert_eq!(statuses.len(), 2);
    assert_eq!(
        statuses[0].address,
        first_socket.local_addr().unwrap().to_string()
    );
    assert_eq!(
        statuses[1].address,
        second_socket.local_addr().unwrap().to_string()
    );
    assert!(
        statuses
            .iter()
            .all(|status| status.status == SecondaryStatus::Unreachable)
    );
}

/// Verify that a diagnostic keeps its selected peer and a later selection refreshes it.
#[tokio::test]
async fn diagnostic_reuses_resolved_target_after_secondary_changes() {
    let cx = context().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    secondary::create(
        &cx,
        &Caller::socket(),
        &CreateSecondaryRequest {
            name: "selected".to_string(),
            address: "127.0.0.1:1".to_string(),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();
    let target = SecondaryTarget {
        secondary: secondary::lookup_by_name(&cx, "selected").await.unwrap(),
        addresses: Ok(vec![addr]),
    };
    secondary::update(
        &cx,
        &Caller::socket(),
        "selected",
        &UpdateSecondaryRequest {
            address: Some("127.0.0.1:2".to_string()),
            enabled: Some(false),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();
    let server = tokio::spawn(async move {
        for rcode in [OptRcode::REFUSED, OptRcode::NOERROR] {
            let mut buffer = [0; 4096];
            let (len, peer) = time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let query = ParsedQuery::parse(&buffer[..len], Keepalive::None).unwrap();
            let response = query
                .build_signed_error_response(rcode, None, None)
                .unwrap();
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let zone_name = cx.config().dns.catalog_zone_name.clone();
    let status = probe_target(&cx, &zone_name, &target, None).await.unwrap();
    assert_eq!(status.address, addr.to_string());
    assert_eq!(status.status, SecondaryStatus::Unreachable);
    assert!(status.error.unwrap().contains("RCODE 5"));
    let reports = notify::send_notify_to_targets(&cx, &zone_name, [&target])
        .await
        .unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].address, addr.to_string());
    assert!(reports[0].error.is_none());
    assert_eq!(target.client_ips(), vec![addr.ip()]);
    server.await.unwrap();

    assert!(secondary::resolve_enabled(&cx).await.unwrap().is_empty());
    let next = SecondaryTarget::resolve(
        secondary::lookup_by_name(&cx, "selected").await.unwrap(),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(
        next.addresses.unwrap(),
        vec!["127.0.0.1:2".parse().unwrap()]
    );
}

/// Verify that each stage reports the same resolution failure without retrying the address.
#[tokio::test]
async fn diagnostic_reuses_resolution_failure_for_probe_and_notify() {
    let cx = context().await;
    secondary::create(
        &cx,
        &Caller::socket(),
        &CreateSecondaryRequest {
            name: "failed".to_string(),
            address: "127.0.0.1:1".to_string(),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();
    let error = Arc::new(ResolveAddressError::NoAddresses);
    assert!(
        std::error::Error::source(&ProbeSoaError::Resolve(error.clone().into()))
            .unwrap()
            .is::<ResolveAddressError>()
    );
    let target = SecondaryTarget {
        secondary: secondary::lookup_by_name(&cx, "failed").await.unwrap(),
        addresses: Err(error.clone()),
    };
    let zone_name = &cx.config().dns.catalog_zone_name;
    let probe = probe_resolved(zone_name, &target, Duration::from_secs(1))
        .await
        .unwrap();
    let Err(ProbeSoaError::Resolve(probe_error)) = probe.serial else {
        panic!("the original resolution failure was lost");
    };
    assert!(ptr::eq(
        std::error::Error::source(&probe_error)
            .unwrap()
            .downcast_ref::<ResolveAddressError>()
            .unwrap(),
        error.as_ref()
    ));
    assert!(target.client_ips().is_empty());
    let status = probe_target(&cx, zone_name, &target, None).await.unwrap();
    let reports = notify::send_notify_to_targets(&cx, zone_name, [&target])
        .await
        .unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].address, target.secondary.address.to_string());
    assert_eq!(reports[0].error, status.error);
    assert_eq!(status.status, SecondaryStatus::Unreachable);
}

/// Verify that a later missing key aborts preparation before any target receives NOTIFY.
#[tokio::test]
async fn diagnostic_loads_all_keys_before_sending_any_notify() {
    let cx = context().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    secondary::create(
        &cx,
        &Caller::socket(),
        &CreateSecondaryRequest {
            name: "selected".to_string(),
            address: addr.to_string(),
            notify_key_name: None,
        },
    )
    .await
    .unwrap();
    let first = SecondaryTarget {
        secondary: secondary::lookup_by_name(&cx, "selected").await.unwrap(),
        addresses: Ok(vec![addr]),
    };
    // A request-owned row can outlive its referenced key; resolution still succeeded.
    let mut second = first.clone();
    second.secondary.notify_tsig_key_id = Some(TsigKeyId::from(i32::MAX));
    let error =
        notify::send_notify_to_targets(&cx, &cx.config().dns.catalog_zone_name, [&first, &second])
            .await
            .unwrap_err();
    assert!(error.to_string().contains("is missing"));
    let mut buffer = [0; 4096];
    assert!(
        time::timeout(Duration::from_millis(150), socket.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert_eq!(
        cx.notify_preparations().available_permits(),
        notify::CONCURRENT_PREPARATIONS
    );
}
