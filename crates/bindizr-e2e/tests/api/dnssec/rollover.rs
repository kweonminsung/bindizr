use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify a complete rollover with combined signing keys.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_csk_rollover_preserves_signed_zone() {
    let app = TestApp::start().await;
    // The publish wait is the zone TTL plus the SOA refresh (RFC 7583,
    // Section 3.2.1); both short, the rollover reaches promotion inside the test.
    let zone_name = app.zone_name("rollover.example");
    let (status, body) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "default_ttl": 60,
                "refresh": 1,
                "serial": 10,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let zone_name = zone_name.as_str();
    let serial_before = body["zone"]["serial"].as_i64().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body;
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
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let dnssec = &body;
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
    // Pre-publishing changes the DNSKEY record set secondaries hold, so each
    // rollover step rides the serial/IXFR mechanics.
    assert_eq!(dnssec["serial"].as_i64().unwrap(), serial_before + 2);

    let (status, body) = app
        .send_request(
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
        let (status, _) = app.send_request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
    tokio::time::sleep(std::time::Duration::from_secs(62)).await;

    // No parent stands in here, so the DS is taken on the caller's word.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen?skip_ds_check=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let dnssec = &body;
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
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_NO_ROLLOVER_IN_PROGRESS");
}
