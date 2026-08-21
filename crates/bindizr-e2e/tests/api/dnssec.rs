use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

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

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/dnssec/ds"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let ds_records = body["ds_records"].as_array().unwrap();
    assert_eq!(ds_records.len(), 1);
    assert_eq!(ds_records[0]["key_tag"], key_tag);

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
            &format!("/zones/{zone_name}/versions?all=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let all_serials = listed_serials(&body);
    assert!(
        all_serials.contains(&signer_serial),
        "all=true must include signer-only serials: {all_serials:?}"
    );

    // Without the going-insecure acknowledgement the disable is refused.
    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "confirm_insecure": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["enabled"], false);
    assert!(body["dnssec"]["keys"].as_array().unwrap().is_empty());

    let (status, body) = app
        .request(
            Method::DELETE,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "confirm_insecure": true })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_NOT_ENABLED");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_csk_rollover_lifecycle() {
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

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
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
async fn dnssec_enable_with_nsec3_and_split_keys() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "denial": "nsec3", "split_keys": true })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body["dnssec"];
    assert_eq!(dnssec["denial"], "nsec3");

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
    app.run_cli_success(&[
        "zone",
        "token-policy",
        "add",
        zone_name,
        "--token",
        &scoped_name,
    ])
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
