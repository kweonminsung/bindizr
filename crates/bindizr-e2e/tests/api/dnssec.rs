use std::net::UdpSocket;

use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{FakeParent, TestApp, TestAppOptions};

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
async fn dnssec_enable_status_sign_disable_lifecycle() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let serial_before = zone["serial"].as_i64().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body["dnssec"];
    assert_eq!(dnssec["zone_name"], zone_name);
    assert_eq!(dnssec["enabled"], true);
    // Enabling without a policy signs under the seeded `default` policy.
    assert_eq!(dnssec["policy"]["name"], "default");
    assert_eq!(dnssec["policy"]["denial"], "nsec");

    let keys = dnssec["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["algorithm"], "ecdsap256sha256");
    let key_tag = keys[0]["key_tag"].as_i64().unwrap();
    assert!(key_tag > 0, "key tag must be positive: {key_tag}");

    let ds_records = dnssec["ds_records"].as_array().unwrap();
    assert_eq!(ds_records.len(), 1);
    let presentation = ds_records[0]["presentation"].as_str().unwrap();
    assert!(presentation.contains("IN DS"), "{presentation}");
    assert!(
        presentation.contains(&format!("{zone_name}.")),
        "{presentation}"
    );

    // Signing changes the zone content, so it rides the serial/IXFR mechanics.
    assert_eq!(dnssec["serial"].as_i64().unwrap(), serial_before + 1);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_ALREADY_ENABLED");

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["enabled"], true);
    assert_eq!(body["dnssec"]["keys"][0]["key_tag"], key_tag);

    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/sign"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(app.zone_serial(zone_name).await, serial_before + 2);

    // The enable serial carried only signer-generated changes, so once it is
    // no longer current the default version listing hides it; `all` shows it.
    let signer_serial = serial_before + 1;
    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let listed_serials = |body: &serde_json::Value| -> Vec<i64> {
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["serial"].as_i64().unwrap())
            .collect()
    };
    let default_serials = listed_serials(&body);
    assert!(
        !default_serials.contains(&signer_serial),
        "signer-only serial should be hidden by default: {default_serials:?}"
    );
    assert!(
        default_serials.contains(&(serial_before + 2)),
        "the current serial is always listed: {default_serials:?}"
    );

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/versions?include_signer_serials=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let all_serials = listed_serials(&body);
    assert!(
        all_serials.contains(&signer_serial),
        "include_signer_serials=true must include signer-only serials: {all_serials:?}"
    );

    // A DS secures a delegation, so the NS RRset must exist first.
    let ds_value = "12345 13 2 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383";
    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "sub", "record_type": "DS", "value": ds_value,
                "ttl": 3600, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "sub", "record_type": "NS", "value": "ns1.delegated-child.example.",
                "ttl": 3600, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "sub", "record_type": "DS", "value": ds_value,
                "ttl": 3600, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // The unsigned export must stay the import-compatible user plane.
    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/export?signed=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let signed_export = body.as_str().unwrap().to_string();
    assert!(
        signed_export.contains("\tIN\tDNSKEY\t257 3 "),
        "{signed_export}"
    );
    assert!(
        signed_export.contains("\tIN\tRRSIG\tSOA "),
        "{signed_export}"
    );
    assert!(signed_export.contains("\tIN\tNSEC\t"), "{signed_export}");
    // The delegation: DS signed as the parent's data, its NS served unsigned.
    assert!(
        signed_export.contains("sub\t3600\tIN\tDS\t12345 13 2 "),
        "{signed_export}"
    );
    assert!(
        signed_export.contains("\tIN\tRRSIG\tDS "),
        "{signed_export}"
    );

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.as_str().unwrap().contains("RRSIG"), "{body}");

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{zone_name}/dnssec?skip_ds_check=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["enabled"], false);
    assert!(body["dnssec"].get("policy").is_none());
    assert!(body["dnssec"]["keys"].as_array().unwrap().is_empty());

    let (status, body) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_NOT_ENABLED");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_csk_rollover_lifecycle() {
    let app = TestApp::start().await;
    // A zero publish hold-down lets the rollover be confirmed as soon as the
    // zone's DNSKEY TTL allows; the hold-down never drops below that TTL, so
    // the minimum TTL is the shortest wait that still reaches promotion.
    let policy_name = format!("{}-fast", app.namespace());
    let (status, _) = app
        .request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name, "rollover_publish_holddown_secs": 0 })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_name = app.zone_name("rollover.example");
    let (status, body) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "default_ttl": 60,
                "serial": 10,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_name = zone_name.as_str();
    let serial_before = body["zone"]["serial"].as_i64().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": policy_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body["dnssec"];
    assert_eq!(dnssec["policy"]["name"], policy_name);
    let keys = dnssec["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["role"], "csk");
    assert_eq!(keys[0]["state"], "active");
    let old_key_id = keys[0]["id"].as_i64().unwrap();
    let ds_records = dnssec["ds_records"].as_array().unwrap();
    assert_eq!(ds_records.len(), 1);
    let old_ds = ds_records[0]["presentation"].as_str().unwrap().to_string();
    assert_eq!(dnssec["serial"].as_i64().unwrap(), serial_before + 1);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let dnssec = &body["dnssec"];
    let keys = dnssec["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let published = keys
        .iter()
        .find(|key| key["state"] == "published")
        .expect("rollover start pre-publishes the replacement key");
    assert_eq!(published["role"], "csk");
    let new_key_id = published["id"].as_i64().unwrap();
    let active = keys
        .iter()
        .find(|key| key["state"] == "active")
        .expect("the old key keeps signing during the rollover");
    assert_eq!(active["id"].as_i64().unwrap(), old_key_id);

    // Double-DS: both keys are in the parent DS set while it switches over,
    // so the old DS stays alongside the new key's.
    let ds_records = dnssec["ds_records"].as_array().unwrap();
    assert_eq!(ds_records.len(), 2);
    assert!(
        ds_records.iter().any(|ds| ds["presentation"] == old_ds),
        "old DS left the set during the rollover: {ds_records:?}"
    );
    // Pre-publishing changes the DNSKEY RRset secondaries hold, so each
    // rollover step rides the serial/IXFR mechanics.
    assert_eq!(dnssec["serial"].as_i64().unwrap(), serial_before + 2);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_ROLLOVER_IN_PROGRESS");

    // A replacement resolvers cannot have learned yet may not sign;
    // `skip_ds_check` skips only the parent check, never the hold-down.
    for path in [
        format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
        format!("/zones/{zone_name}/dnssec/rollover/ds-seen?skip_ds_check=true"),
    ] {
        let (status, _) = app.request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;

    // No parent stands in here, so the DS is taken on the caller's word.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen?skip_ds_check=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let dnssec = &body["dnssec"];
    let keys = dnssec["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let key_by_id = |id: i64| {
        keys.iter()
            .find(|key| key["id"].as_i64() == Some(id))
            .unwrap_or_else(|| panic!("no key with id {id} in {keys:?}"))
    };
    assert_eq!(key_by_id(new_key_id)["state"], "active");
    assert_eq!(key_by_id(old_key_id)["state"], "retired");

    // Retired keys leave the CDS/DS set, telling the parent to drop their DS.
    let ds_records = dnssec["ds_records"].as_array().unwrap();
    assert_eq!(ds_records.len(), 1);
    assert_eq!(ds_records[0]["key_tag"], key_by_id(new_key_id)["key_tag"]);
    assert_eq!(dnssec["serial"].as_i64().unwrap(), serial_before + 3);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_NO_ROLLOVER_IN_PROGRESS");
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
    parent.set_ds(vec![(old_key_tag, 60)]);

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

    parent.set_ds(vec![(old_key_tag, 60), (new_key_tag, 60)]);
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
async fn dnssec_enable_with_nsec3_and_split_keys() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let policy_name = format!("{}-nsec3-split", app.namespace());
    let (status, _) = app
        .request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name, "denial": "nsec3", "split_keys": true })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": policy_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body["dnssec"];
    assert_eq!(dnssec["policy"]["denial"], "nsec3");
    assert_eq!(dnssec["policy"]["split_keys"], true);

    let keys = dnssec["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let key_with_role = |role: &str| {
        keys.iter()
            .find(|key| key["role"] == role)
            .unwrap_or_else(|| panic!("no {role} key in {keys:?}"))
    };
    let ksk = key_with_role("ksk");
    assert_eq!(ksk["state"], "active");
    assert_eq!(key_with_role("zsk")["state"], "active");

    // The parent DS set names only SEP keys, so the ZSK contributes no DS.
    let ds_records = dnssec["ds_records"].as_array().unwrap();
    assert_eq!(ds_records.len(), 1);
    assert_eq!(ds_records[0]["key_tag"], ksk["key_tag"]);

    // A split-key zone has two rollable keys, so the role must be named.
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({ "role": "zsk" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["dnssec"]["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
    let published = keys
        .iter()
        .find(|key| key["state"] == "published")
        .expect("rollover start pre-publishes the replacement key");
    assert_eq!(published["role"], "zsk");

    // ds-seen has no meaning for a ZSK rollover — no parent DS is involved —
    // and must not bypass the publish hold-down.
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn records_listing_signed_pages_the_derived_plane() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www",
                "record_type": "A",
                "value": "192.0.2.10",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let user_total = body["pagination"]["total"].as_u64().unwrap();
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["id"].is_i64()),
        "the unsigned listing holds only addressable user records"
    );

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(
        body["pagination"]["total"].as_u64().unwrap() as usize,
        items.len()
    );
    assert!(body["pagination"]["total"].as_u64().unwrap() > user_total);
    let derived: Vec<_> = items.iter().filter(|item| item["id"].is_null()).collect();
    for record_type in ["DNSKEY", "NSEC", "RRSIG"] {
        assert!(
            derived
                .iter()
                .any(|item| item["record_type"] == record_type),
            "signed listing must carry a {record_type} row: {items:?}"
        );
    }
    assert!(derived.iter().all(|item| item["priority"].is_null()));

    // The derived plane pages after the user records under one offset space.
    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true&offset={user_total}&limit=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| item["id"].is_null()));

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true&record_type=RRSIG"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert!(!items.is_empty());
    assert!(items.iter().all(|item| item["record_type"] == "RRSIG"));

    // A derived type is only addressable through the signed view.
    let (status, _) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&record_type=RRSIG"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_enable_requires_a_global_token() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        require_authentication: true,
        ..TestAppOptions::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Grant the zone to the scoped token so the 403 proves the global
    // requirement, not zone invisibility (which would read as 404).
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&["token", "grant", &scoped_name, zone_name])
        .await;
    app.set_auth_token(scoped_token);

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "FORBIDDEN");
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
    parent.set_ds(vec![(key_tag, 3600)]);

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
    assert_eq!(delegation["parent_servers"], json!([parent.addr()]));
    assert_eq!(delegation["discovered"], false);
    assert_eq!(
        delegation["keys"],
        json!([{ "key_tag": key_tag, "role": "csk", "state": "active", "ds_published": true }])
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
