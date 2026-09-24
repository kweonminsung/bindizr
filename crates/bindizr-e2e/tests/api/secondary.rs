use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{
    TestApp, assert_cli_failure_contains,
    dns::{
        notify::{FakeSecondary, ReceivedNotify, SERVED_SERIAL},
        nsupdate::create_tsig_key,
    },
};

/// Verify secondary registration, retrieval, update, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn secondary_create_read_update_delete() {
    let app = TestApp::start().await;
    let name = format!("{}-ns2", app.namespace());

    // The address is stored with its port spelled out and lowercased, so one
    // server has one row whichever way it is written.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": name, "address": "NS2.Example.net" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["secondary"]["name"], name);
    assert_eq!(body["secondary"]["address"], "ns2.example.net:53");
    assert_eq!(body["secondary"]["enabled"], true);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": name, "address": "192.0.2.7" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "SECONDARY_CONFLICT");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": format!("{name}-again"), "address": "ns2.example.net:53" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "SECONDARY_CONFLICT");

    let (status, body) = app
        .send_request(Method::GET, &format!("/secondaries/{name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secondary"]["address"], "ns2.example.net:53");

    let (status, body) = app.send_request(Method::GET, "/secondaries", None).await;
    assert_eq!(status, StatusCode::OK);
    let listed = body["items"].as_array().unwrap();
    assert!(listed.iter().any(|item| item["name"] == name), "{body}");

    // A partial update keeps the fields it leaves out.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["secondary"]["enabled"], false);
    assert_eq!(body["secondary"]["address"], "ns2.example.net:53");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({ "address": "[2001:db8::7]:5300" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["secondary"]["address"], "[2001:db8::7]:5300");
    assert_eq!(body["secondary"]["enabled"], false);

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{name}"),
            Some(json!({ "address": "not a host" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, _) = app
        .send_request(Method::DELETE, &format!("/secondaries/{name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .send_request(Method::GET, &format!("/secondaries/{name}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "SECONDARY_NOT_FOUND");
}

/// Verify that a secondary name must be a plain identifier and its address a host[:port].
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn secondary_rejects_a_bad_name_or_address() {
    let app = TestApp::start().await;

    for (name, address) in [
        ("ns 2", "192.0.2.7"),
        ("ns2/eu", "192.0.2.7"),
        ("ns2", ""),
        ("ns2", "192.0.2.7:port"),
        ("ns2", "192.0.2.7:0"),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/secondaries",
                Some(json!({ "name": format!("{}-{name}", app.namespace()), "address": address })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{name:?} {address:?}: {body}"
        );
        assert_eq!(body["code"], "INVALID_INPUT");
    }
}

/// Verify that NOTIFY to a secondary registered with a NOTIFY key is signed
/// with it, that the signed answer is accepted, and that a server holding
/// another key fails the NOTIFY rather than passing it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn notify_is_signed_for_a_secondary_with_a_notify_key() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    // `domain` renders a name without its root dot.
    let expected_zone = zone_name.to_string();

    let key = create_tsig_key(&app, "notify-key", false).await;
    let signed_receiver = FakeSecondary::start(Some(&key));
    let plain_receiver = FakeSecondary::start(None);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": "signed", "address": signed_receiver.addr(), "notify_key": key.name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["secondary"]["notify_key"], key.name);
    let plain = app.create_secondary("plain", &plain_receiver.addr()).await;
    assert_eq!(plain["secondary"]["notify_key"], json!(null));

    // NOTIFY is sent before the request is answered (no batching window).
    let (status, body) = app
        .send_request(Method::POST, &format!("/zones/{zone_name}/notify"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        signed_receiver.received(),
        vec![ReceivedNotify {
            zone: expected_zone.clone(),
            signed: true,
            verified: true,
        }]
    );
    assert_eq!(
        plain_receiver.received(),
        vec![ReceivedNotify {
            zone: expected_zone.clone(),
            signed: false,
            verified: false,
        }]
    );

    // The key is in use while a secondary signs with it.
    let (status, body) = app
        .send_request(Method::DELETE, "/tsig-keys/notify-key", None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "TSIG_KEY_IN_USE");

    // A server that holds another key answers with the TSIG error, which
    // the NOTIFY reports instead of an acknowledgement.
    let other = create_tsig_key(&app, "other-key", false).await;
    let wrong_receiver = FakeSecondary::start(Some(&other));
    let (status, body) = app
        .send_request(
            Method::PUT,
            "/secondaries/signed",
            Some(json!({ "address": wrong_receiver.addr() })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app
        .send_request(Method::POST, &format!("/zones/{zone_name}/notify"), None)
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert!(body["error"].to_string().contains("TSIG"), "{body}");
    assert_eq!(
        wrong_receiver.received(),
        vec![ReceivedNotify {
            zone: expected_zone,
            signed: true,
            verified: false,
        }]
    );

    // An empty key name sends NOTIFY unsigned again and frees the key.
    let (status, body) = app
        .send_request(
            Method::PUT,
            "/secondaries/signed",
            Some(json!({ "notify_key": "" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["secondary"]["notify_key"], json!(null));
    let (status, _) = app
        .send_request(Method::DELETE, "/tsig-keys/notify-key", None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Verify that a check reports where the address resolves, the catalog
/// serial against Bindizr's, and the NOTIFY outcome, and that the CLI exits
/// non-zero for a secondary that fails it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn secondary_check_reports_resolution_catalog_and_notify() {
    let app = TestApp::start_local().await;
    // With no member zone the catalog serial is 1, the serial the fake serves.
    let receiver = FakeSecondary::start(None);
    app.create_secondary("fake", &receiver.addr()).await;
    // Nothing listens on port 1, so this one resolves but never answers.
    app.create_secondary("dead", "127.0.0.1:1").await;

    let (status, body) = app
        .send_request(Method::POST, "/secondaries/fake/check", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["addresses"], json!([receiver.addr()]));
    assert_eq!(body["catalog_zone"], "catalog.bindizr");
    assert_eq!(body["catalog"]["status"], "in_sync");
    assert_eq!(body["catalog"]["visible_serial"], SERVED_SERIAL);
    assert_eq!(body["catalog_serial"], SERVED_SERIAL);
    assert_eq!(body["notifies"][0]["accepted"], true);
    assert_eq!(receiver.received().len(), 1);

    let (status, body) = app
        .send_request(Method::POST, "/secondaries/dead/check", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["addresses"], json!(["127.0.0.1:1"]));
    assert_eq!(body["catalog"]["status"], "unreachable");
    assert_eq!(body["notifies"][0]["accepted"], false);

    let checked = app.run_cli_success(&["secondary", "check", "fake"]).await;
    assert!(
        checked.contains("in sync at serial 1") && checked.contains("accepted"),
        "{checked}"
    );
    let args = ["secondary", "check", "dead"];
    let failed = app.run_cli(&args).await;
    assert_cli_failure_contains(&args, &failed, "Secondary 'dead' failed the check");
}
