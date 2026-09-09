//! The parent side of DNSSEC over the API: the DS its nameservers serve
//! gates disabling and the ds-seen promotion.

use std::net::UdpSocket;

use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{FakeParent, ServedDs, TestApp};

/// A `host:port` nothing listens on, standing in for an unreachable parent.
fn closed_parent_addr() -> String {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("failed to bind an ephemeral port");
    socket
        .local_addr()
        .expect("failed to read the ephemeral port")
        .to_string()
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_ds_seen_checks_the_parent_even_when_the_holddown_is_skipped() {
    let app = TestApp::start_local().await;
    let parent = FakeParent::start();
    let policy_name = format!("{}-fast", app.namespace());
    let (status, _) = app
        .request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name, "rollover_publish_holddown_secs": 0 })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_name = app.zone_name("ds-seen.example");
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "default_ttl": 60,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_name = zone_name.as_str();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": policy_name, "parent_ns_addrs": parent.addr() })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let old_key_tag = body["dnssec"]["keys"][0]["key_tag"].as_u64().unwrap() as u16;
    parent.set_ds(vec![ServedDs::from_status(
        &body["dnssec"],
        old_key_tag,
        60,
    )]);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let new_key_tag = body["dnssec"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["state"] == "published")
        .expect("rollover start pre-publishes the replacement key")["key_tag"]
        .as_u64()
        .unwrap() as u16;
    // The parent still serves only the old DS: the new key must not sign yet.
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen?skip_holddown=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_DS_NOT_PUBLISHED");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(&new_key_tag.to_string()),
        "{body}"
    );

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/check-ds"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let delegation_keys = body["dnssec"]["delegation"]["keys"].as_array().unwrap();
    let delegation_key = |tag: u16| {
        delegation_keys
            .iter()
            .find(|key| key["key_tag"] == tag)
            .unwrap_or_else(|| panic!("no key tag {tag} in {delegation_keys:?}"))
    };
    assert_eq!(delegation_key(old_key_tag)["ds_published"], true);
    assert_eq!(delegation_key(new_key_tag)["ds_published"], false);
    assert!(
        delegation_key(new_key_tag)["eligible_at"].is_string(),
        "{body}"
    );

    parent.set_ds(vec![
        ServedDs::from_status(&body["dnssec"], old_key_tag, 60),
        ServedDs::from_status(&body["dnssec"], new_key_tag, 60),
    ]);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen?skip_holddown=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["dnssec"]["keys"].as_array().unwrap();
    let key_by_tag = |tag: u16| {
        keys.iter()
            .find(|key| key["key_tag"] == tag)
            .unwrap_or_else(|| panic!("no key tag {tag} in {keys:?}"))
    };
    assert_eq!(key_by_tag(new_key_tag)["state"], "active");
    assert_eq!(key_by_tag(old_key_tag)["state"], "retired");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_disable_waits_for_the_parent_to_drop_the_ds() {
    let app = TestApp::start_local().await;
    let parent = FakeParent::start();
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": parent.addr() })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["dnssec"]["parent_ns_addrs"], parent.addr());
    assert!(body["dnssec"]["delegation"].is_null(), "{body}");
    let key_tag = body["dnssec"]["keys"][0]["key_tag"].as_u64().unwrap() as u16;
    parent.set_ds(vec![ServedDs::from_status(&body["dnssec"], key_tag, 3600)]);

    // The parent still delegates trust: dropping the signatures now would
    // make the zone bogus.
    let (status, body) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_DS_PUBLISHED");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(&key_tag.to_string()),
        "{body}"
    );

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/check-ds"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let delegation = &body["dnssec"]["delegation"];
    assert_eq!(delegation["ds_state"], "published");
    assert_eq!(delegation["ds_key_tags"], json!([key_tag]));
    assert_eq!(delegation["ds_ttl"], 3600);
    assert_eq!(delegation["parent_ns_addrs"], json!([parent.addr()]));
    assert_eq!(delegation["discovered"], false);
    let key_id = body["dnssec"]["keys"][0]["id"].clone();
    assert_eq!(
        delegation["keys"],
        json!([{ "id": key_id, "key_tag": key_tag, "role": "csk", "state": "active", "ds_published": true }])
    );

    // A status read asks no one; only the check does.
    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["dnssec"]["delegation"].is_null(), "{body}");

    parent.set_ds(Vec::new());
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/check-ds"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["delegation"]["ds_state"], "hidden");
    assert_eq!(body["dnssec"]["delegation"]["ds_key_tags"], json!([]));
    assert!(body["dnssec"]["delegation"]["ds_ttl"].is_null(), "{body}");
    assert_eq!(
        body["dnssec"]["delegation"]["keys"][0]["ds_published"],
        false
    );

    let (status, _) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["enabled"], false);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_disable_is_refused_until_the_parent_can_be_asked() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": closed_parent_addr() })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // A parent that does not answer may still serve the DS.
    let (status, body) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_DS_UNVERIFIED");

    // A settings change must name something to change.
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    let parent = FakeParent::start();
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": format!(" {} ,", parent.addr()) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["parent_ns_addrs"], parent.addr());

    // An empty list returns the zone to parent discovery.
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": "" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["dnssec"]["parent_ns_addrs"].is_null(), "{body}");

    let (status, _) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": parent.addr() })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let zone_name = app.zone_name("dnssec-skip.example");
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "default_ttl": 3600
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": closed_parent_addr() })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{zone_name}/dnssec?skip_ds_check=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_ds_seen_requires_the_exact_ds_on_every_parent_server() {
    let app = TestApp::start_local().await;
    let first_parent = FakeParent::start();
    let second_parent = FakeParent::start();
    let zone_name = app.zone_name("ds-seen-servers.example");
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "default_ttl": 60,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_name = zone_name.as_str();

    let parent_ns_addrs = format!("{},{}", first_parent.addr(), second_parent.addr());
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": parent_ns_addrs })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let old_key_tag = body["dnssec"]["keys"][0]["key_tag"].as_u64().unwrap() as u16;
    let old_ds = ServedDs::from_status(&body["dnssec"], old_key_tag, 60);
    first_parent.set_ds(vec![old_ds.clone()]);
    second_parent.set_ds(vec![old_ds.clone()]);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let new_key_tag = body["dnssec"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["state"] == "published")
        .expect("rollover start pre-publishes the replacement key")["key_tag"]
        .as_u64()
        .unwrap() as u16;
    let new_ds = ServedDs::from_status(&body["dnssec"], new_key_tag, 60);

    let ds_seen_path = format!("/zones/{zone_name}/dnssec/rollover/ds-seen?skip_holddown=true");
    let new_key_published = |body: &serde_json::Value| {
        body["dnssec"]["delegation"]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["key_tag"] == new_key_tag)
            .expect("the replacement key is a delegation key")["ds_published"]
            .clone()
    };

    // A DS with the new key's tag but another digest is another key's DS.
    first_parent.set_ds(vec![old_ds.clone(), new_ds.clone().with_wrong_digest()]);
    second_parent.set_ds(vec![old_ds.clone(), new_ds.clone().with_wrong_digest()]);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/check-ds"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(new_key_published(&body), false, "{body}");
    let (status, body) = app.request(Method::POST, &ds_seen_path, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "DNSSEC_DS_NOT_PUBLISHED");

    // One parent server lagging behind the other still blocks promotion.
    first_parent.set_ds(vec![old_ds.clone(), new_ds.clone()]);
    second_parent.set_ds(vec![old_ds.clone()]);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/check-ds"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["dnssec"]["delegation"]["ds_state"], "published");
    assert_eq!(new_key_published(&body), false, "{body}");
    let (status, body) = app.request(Method::POST, &ds_seen_path, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "DNSSEC_DS_NOT_PUBLISHED");

    second_parent.set_ds(vec![old_ds, new_ds]);
    let (status, body) = app.request(Method::POST, &ds_seen_path, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["dnssec"]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key["key_tag"] == new_key_tag && key["state"] == "active"),
        "{body}"
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_ds_seen_accepts_the_sha1_ds_a_parent_computed_itself() {
    let app = TestApp::start_local().await;
    let parent = FakeParent::start();
    let zone_name = app.zone_name("ds-seen-sha1.example");
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "default_ttl": 60,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_name = zone_name.as_str();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": parent.addr() })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let old_key_tag = body["dnssec"]["keys"][0]["key_tag"].as_u64().unwrap() as u16;
    let old_ds = ServedDs::from_status(&body["dnssec"], old_key_tag, 60);
    parent.set_ds(vec![old_ds.clone()]);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let new_key_tag = body["dnssec"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["state"] == "published")
        .expect("rollover start pre-publishes the replacement key")["key_tag"]
        .as_u64()
        .unwrap() as u16;
    // Only a SHA-1 DS, as a parent digesting the DNSKEY itself may
    // register; status never renders one.
    let new_ds = ServedDs::sha1_from_status(&body["dnssec"], zone_name, new_key_tag, 60);
    parent.set_ds(vec![old_ds, new_ds]);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/check-ds"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["dnssec"]["delegation"]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["key_tag"] == new_key_tag)
            .expect("the replacement key is a delegation key")["ds_published"],
        true,
        "{body}"
    );

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen?skip_holddown=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["dnssec"]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key["key_tag"] == new_key_tag && key["state"] == "active"),
        "{body}"
    );
}
