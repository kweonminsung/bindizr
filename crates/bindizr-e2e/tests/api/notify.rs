use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use domain::base::iana::Rcode;
use domain::base::{Message, MessageBuilder};
use reqwest::{Method, StatusCode};
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::time;

use crate::api::common::FakeSecondary;
use crate::common::{TestApp, TestAppOptions};

/// Verify that committed changes and an all-zones round send promptly while other ACKs are silent.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn silent_notify_waits_do_not_delay_commits_or_later_zones() {
    let app = Arc::new(
        TestApp::start_with_options(TestAppOptions {
            notify_batch_ms: 10,
            notify_timeout_secs: 3,
            ..Default::default()
        })
        .await,
    );

    let mut zone_names = Vec::new();

    for index in 0..33 {
        let zone_name = app.zone_name(&format!("zone-{index:02}.example"));
        let (status, body) = app
            .send_request(
                Method::POST,
                "/zones",
                Some(json!({
                    "name": zone_name,
                    "mname": "ns.example",
                    "rname": "admin@example.com",
                    "refresh": 1
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
        zone_names.push(zone_name);
    }

    // Let catalog jobs from fixture creation finish before adding the silent peer.
    time::sleep(Duration::from_millis(50)).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.create_secondary("silent", &socket.local_addr().unwrap().to_string())
        .await;

    let mut buffer = [0; 4096];
    let mut queued = Vec::new();

    for zone_name in zone_names.iter().take(2) {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({ "zone_name": zone_name, "name": "www", "type": "A", "value": "192.0.2.50" })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (len, peer) = time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let query = Message::from_octets(buffer[..len].to_vec()).unwrap();

        assert_eq!(
            &query.sole_question().unwrap().qname().to_string(),
            zone_name
        );
        queued.push((query, peer));
    }

    for (query, peer) in queued {
        socket
            .send_to(
                &MessageBuilder::new_vec()
                    .start_answer(&query, Rcode::NOERROR)
                    .unwrap()
                    .finish(),
                peer,
            )
            .await
            .unwrap();
    }

    let task_app = app.clone();

    let task =
        tokio::spawn(async move { task_app.send_request(Method::POST, "/notify", None).await });

    let mut seen = HashSet::new();
    let mut peers = HashSet::new();
    let mut replies = Vec::new();

    time::timeout(Duration::from_secs(1), async {
        while seen.len() < zone_names.len() {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = Message::from_octets(buffer[..len].to_vec()).unwrap();
            seen.insert(query.sole_question().unwrap().qname().to_string());
            peers.insert(peer);
            replies.push((query, peer));
        }
    })
    .await
    .unwrap();

    assert_eq!(seen, zone_names.into_iter().collect());
    assert_eq!(
        peers.len(),
        1,
        "all active zones share one socket to the same peer"
    );

    for (query, peer) in replies {
        socket
            .send_to(
                &MessageBuilder::new_vec()
                    .start_answer(&query, Rcode::NOERROR)
                    .unwrap()
                    .finish(),
                peer,
            )
            .await
            .unwrap();
    }

    let (status, body) = task.await.unwrap();

    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Verify that NOTIFY reaches one or all zones, with optional serial advancement.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_supports_one_or_all_zones_with_optional_serial_bump() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(Method::POST, &format!("/zones/{zone_name}/notify"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name}")
    );

    let (status, body) = app.send_request(Method::POST, "/notify", None).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["message"], "NOTIFY sent successfully for all zones");

    let before_serial = app.read_zone_serial(zone_name).await;

    // bump_serial makes secondaries transfer even when nothing changed.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/notify?bump_serial=true"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name} (serial bumped)")
    );

    let after_serial = app.read_zone_serial(zone_name).await;

    assert!(after_serial > before_serial);

    let missing_zone_name = app.zone_name("missing.example.com");

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{missing_zone_name}/notify"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(&format!("zone with name '{missing_zone_name}' not found"))
    );
}

/// Verify that a scoped token cannot notify the virtual catalog zone, which has no database row
/// a zone grant can reference.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_rejects_catalog_zone_notify() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token.clone());

    let (_, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, _) = app
        .send_request(Method::POST, "/zones/catalog.bindizr/notify", None)
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);

    app.set_auth_token(admin_token);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/zones/catalog.bindizr/notify?bump_serial=true",
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["message"],
        "NOTIFY sent successfully for zone: catalog.bindizr"
    );
}

/// Verify that a one-second REFRESH bounds a ten-second batch and shutdown flushes the next batch.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn queued_notify_caps_delay_coalesces_writes_and_flushes_on_shutdown() {
    let app = TestApp::start_with_options(TestAppOptions {
        notify_batch_ms: 10000,
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "refresh": 1 })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let receiver = FakeSecondary::start(None);

    app.create_secondary("receiver", &receiver.addr()).await;

    for index in 0..3 {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "zone_name": zone_name, "name": format!("www{index}"), "type": "A", "value": "192.0.2.50"
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    time::timeout(Duration::from_secs(3), async {
        while !receiver
            .received()
            .iter()
            .any(|notify| notify.zone_name == zone_name)
        {
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    assert_eq!(
        receiver
            .received()
            .iter()
            .filter(|notify| notify.zone_name == zone_name)
            .count(),
        1
    );

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "refresh": 7200 })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    app.run_cli_success(&["stop"], None).await;
    time::timeout(Duration::from_secs(3), async {
        while receiver
            .received()
            .iter()
            .filter(|notify| notify.zone_name == zone_name)
            .count()
            < 2
        {
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

/// Verify that a matching NOTIMP completes the manual NOTIFY API call successfully.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_reports_completion_when_secondary_does_not_implement_notify() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.create_secondary("notimp", &socket.local_addr().unwrap().to_string())
        .await;
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];

        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let query = Message::from_octets(&buffer[..len]).unwrap();
        let response = MessageBuilder::new_vec()
            .start_answer(&query, Rcode::NOTIMP)
            .unwrap()
            .finish();

        socket.send_to(&response, peer).await.unwrap();
    });
    let (status, body) = app
        .send_request(Method::POST, &format!("/zones/{zone_name}/notify"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    server.await.unwrap();
}

/// Verify that a disabled zone, which the DNS plane answers NOTAUTH for, is
/// not announced: a write to it sends no NOTIFY, and a manual one is refused.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_skips_disabled_zones() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.create_secondary("watcher", &socket.local_addr().unwrap().to_string())
        .await;

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "enabled": false })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({ "zone_name": zone_name, "name": "www", "type": "A", "value": "192.0.2.51" })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The catalog still announces the zone leaving it; the zone itself is silent.
    let mut buffer = [0; 4096];
    let mut announced = Vec::new();

    while let Ok(received) =
        time::timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await
    {
        let (len, _) = received.unwrap();
        let query = Message::from_octets(buffer[..len].to_vec()).unwrap();
        announced.push(query.sole_question().unwrap().qname().to_string());
    }

    assert!(
        !announced.iter().any(|name| name == zone_name),
        "a disabled zone was announced: {announced:?}"
    );

    let serial = app.read_zone_serial(zone_name).await;
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/notify?bump_serial=true"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(app.read_zone_serial(zone_name).await, serial);
}
