use reqwest::{Method, StatusCode};

use crate::common::{TestApp, TestAppOptions};

/// Committed changes and an all-zones round send promptly while other ACKs are silent.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn silent_notify_waits_do_not_delay_commits_or_later_zones() {
    use std::{collections::HashSet, sync::Arc, time::Duration};

    use domain::base::{Message, MessageBuilder, iana::Rcode};
    use serde_json::json;

    let app = Arc::new(
        TestApp::start_with_options(TestAppOptions {
            notify_batch_ms: 10,
            notify_timeout_secs: 3,
            ..Default::default()
        })
        .await,
    );

    let mut names = Vec::new();

    for index in 0..33 {
        let name = app.zone_name(&format!("zone-{index:02}.example"));
        let (status, body) = app.send_request(Method::POST, "/zones", Some(json!({"name": name, "mname": "ns.example", "rname": "admin@example.com", "refresh": 1}))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        names.push(name);
    }

    // Let catalog jobs from fixture creation finish before adding the silent peer.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.create_secondary("silent", &socket.local_addr().unwrap().to_string())
        .await;

    let mut buffer = [0; 4096];
    let mut queued = Vec::new();

    for name in names.iter().take(2) {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({"zone_name": name, "name": "www", "type": "A", "value": "192.0.2.50"})),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (len, peer) =
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
                .await
                .expect("an earlier ACK must not delay the next committed zone")
                .unwrap();
        let query = Message::from_octets(buffer[..len].to_vec()).unwrap();

        assert_eq!(&query.sole_question().unwrap().qname().to_string(), name);
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

    let request_app = app.clone();

    let request = tokio::spawn(async move {
        request_app
            .send_request(Method::POST, "/notify", None)
            .await
    });

    let mut seen = HashSet::new();
    let mut peers = HashSet::new();
    let mut replies = Vec::new();

    tokio::time::timeout(Duration::from_secs(1), async {
        while seen.len() < names.len() {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = Message::from_octets(buffer[..len].to_vec()).unwrap();
            seen.insert(query.sole_question().unwrap().qname().to_string());
            peers.insert(peer);
            replies.push((query, peer));
        }
    })
    .await
    .expect("all zones must start before the three-second ACK timeout");

    assert_eq!(seen, names.into_iter().collect());
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

    let (status, body) = request.await.unwrap();

    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Verify NOTIFY for one or all zones with optional serial advancement.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_supports_one_or_all_zones_with_optional_serial_bump() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A secondary answers NOTAUTH for a zone the catalog has not reached yet.
    app.assert_dns_matches_api(None).await;

    let (status, body) = app
        .send_request(Method::POST, &format!("/zones/{zone_name}/notify"), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name}")
    );

    let (status, body) = app.send_request(Method::POST, "/notify", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "NOTIFY sent successfully for all zones");

    let (status, before) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    let before_serial = before["zone"]["serial"].as_i64().unwrap();

    // bump_serial makes secondaries transfer even when nothing changed.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/notify?bump_serial=true"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        format!("NOTIFY sent successfully for zone: {zone_name} (serial bumped)")
    );

    let (status, after) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    let after_serial = after["zone"]["serial"].as_i64().unwrap();

    assert!(after_serial > before_serial);

    let missing_zone_name = app.zone_name("missing.example.com");

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{missing_zone_name}/notify"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
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
        ..TestAppOptions::default()
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

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["message"],
        "NOTIFY sent successfully for zone: catalog.bindizr"
    );
}

/// A one-second REFRESH bounds a ten-second batch; shutdown flushes the next batch.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn queued_notify_caps_delay_coalesces_writes_and_flushes_on_shutdown() {
    use std::time::Duration;

    use serde_json::json;

    use crate::common::dns::notify::FakeSecondary;

    let app = TestApp::start_with_options(TestAppOptions {
        notify_batch_ms: 10_000,
        ..Default::default()
    })
    .await;
    let zone = app.create_test_zone().await;
    let name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{name}"),
            Some(json!({"refresh": 1})),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let secondary = FakeSecondary::start(None);

    app.create_secondary("receiver", &secondary.addr()).await;

    for index in 0..3 {
        let (status, body) = app.send_request(Method::POST, "/records", Some(json!({
            "zone_name": name, "name": format!("www{index}"), "type": "A", "value": "192.0.2.50"
        }))).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    tokio::time::timeout(Duration::from_secs(3), async {
        while !secondary
            .received()
            .iter()
            .any(|notify| notify.zone == name)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("REFRESH must cap the ten-second batching delay");

    assert_eq!(
        secondary
            .received()
            .iter()
            .filter(|notify| notify.zone == name)
            .count(),
        1
    );

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{name}"),
            Some(json!({"refresh": 7200})),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    app.run_cli_success(&["stop"], None).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while secondary
            .received()
            .iter()
            .filter(|notify| notify.zone == name)
            .count()
            < 2
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("shutdown must flush without the ten-second batching delay");
}

/// A matching NOTIMP completes the manual NOTIFY API call successfully.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_reports_completion_when_secondary_does_not_implement_notify() {
    use domain::base::{Message, MessageBuilder, iana::Rcode};

    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let name = zone["name"].as_str().unwrap();

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.create_secondary("notimp", &socket.local_addr().unwrap().to_string())
        .await;
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];

        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let request = Message::from_octets(&buffer[..len]).unwrap();
        let response = MessageBuilder::new_vec()
            .start_answer(&request, Rcode::NOTIMP)
            .unwrap()
            .finish();

        socket.send_to(&response, peer).await.unwrap();
    });
    let (status, body) = app
        .send_request(Method::POST, &format!("/zones/{name}/notify"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    server.await.unwrap();
}
