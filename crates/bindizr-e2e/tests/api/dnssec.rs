use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

/// Verify the DNSSEC enable, status, re-sign, and disable lifecycle.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_enable_status_sign_disable_lifecycle() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let serial_before = zone["serial"].as_i64().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body["dnssec"];
    assert_eq!(dnssec["zone_name"], zone_name);
    assert_eq!(dnssec["enabled"], true);
    // Enabling without a policy signs under the seeded `default` policy.
    assert_eq!(dnssec["policy"]["name"], "default");
    assert_eq!(dnssec["policy"]["denial"], "nsec3");

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

    // The healthy case status has to be able to show.
    assert!(dnssec["signatures"].as_u64().unwrap() > 0, "{dnssec}");
    assert_eq!(dnssec["expired_signatures"], 0, "{dnssec}");
    assert!(
        dnssec["next_resign_at"].as_str().unwrap()
            < dnssec["earliest_signature_expires_at"].as_str().unwrap(),
        "{dnssec}"
    );

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_ALREADY_ENABLED");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["enabled"], true);
    assert_eq!(body["dnssec"]["keys"][0]["key_tag"], key_tag);

    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/sign"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(app.read_zone_serial(zone_name).await, serial_before + 2);

    // The enable serial carried only signer-generated changes, so once it is
    // no longer current the default version listing hides it; `all` shows it.
    let signer_serial = serial_before + 1;
    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/versions"), None)
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
        .send_request(
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
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "sub", "type": "DS", "value": ds_value,
                "ttl": 3600, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "sub", "type": "NS", "value": "ns1.delegated-child.example.",
                "ttl": 3600, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "sub", "type": "DS", "value": ds_value,
                "ttl": 3600, "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // The unsigned export must stay the import-compatible user plane.
    let (status, body) = app
        .send_request(
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
    assert!(signed_export.contains("\tIN\tNSEC3\t"), "{signed_export}");
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
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.as_str().unwrap().contains("RRSIG"), "{body}");

    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/zones/{zone_name}/dnssec?skip_ds_check=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec"]["enabled"], false);
    assert!(body["dnssec"].get("policy").is_none());
    assert!(body["dnssec"]["keys"].as_array().unwrap().is_empty());

    let (status, body) = app
        .send_request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_NOT_ENABLED");
}

/// Verify a complete rollover with combined signing keys.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_csk_rollover_lifecycle() {
    let app = TestApp::start().await;
    // A short zone TTL is the whole publish wait, so the rollover reaches
    // promotion inside the test.
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
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9"})),
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
        .send_request(
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
    tokio::time::sleep(std::time::Duration::from_secs(61)).await;

    // No parent stands in here, so the DS is taken on the caller's word.
    let (status, body) = app
        .send_request(
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
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_NO_ROLLOVER_IN_PROGRESS");
}

/// Verify DNSSEC enablement with NSEC3 and separate key roles.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_enable_with_nsec3_and_split_keys() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let policy_name = format!("{}-nsec3-split", app.namespace());
    let (status, _) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name, "denial": "nsec3", "split_keys": true })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": policy_name , "parent_ns_addrs": "127.0.0.1:9"})),
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
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = app
        .send_request(
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
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec/rollover/ds-seen"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify that records listing signed pages the derived plane.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn records_listing_signed_pages_the_derived_plane() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "www",
                "type": "A",
                "value": "192.0.2.10",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(
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
        .send_request(
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
    for record_type in ["DNSKEY", "NSEC3", "RRSIG"] {
        assert!(
            derived.iter().any(|item| item["type"] == record_type),
            "signed listing must carry a {record_type} row: {items:?}"
        );
    }
    assert!(derived.iter().all(|item| item["priority"].is_null()));

    // The derived plane pages after the user records under one offset space.
    let (status, body) = app
        .send_request(
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
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&signed=true&type=RRSIG"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert!(!items.is_empty());
    assert!(items.iter().all(|item| item["type"] == "RRSIG"));

    // A derived type is only addressable through the signed view.
    let (status, _) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&type=RRSIG"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Verify that DNSSEC enable requires a global token.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_enable_requires_a_global_token() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
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
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "FORBIDDEN");
}

/// Verify that a signed listing searches the derived plane by name.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_signed_listing_searches_the_derived_plane_by_name() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "searchable", "type": "A", "value": "192.0.2.1",
                "zone_name": zone_name
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // A search used to leave the derived rows out entirely.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&search=searchable&signed=true&limit=1000"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let types: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"A"), "{body}");
    assert!(types.contains(&"RRSIG"), "{body}");

    // Refused rather than quietly answered without the rows it cannot narrow.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&value=192.0.2.1&signed=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("value cannot narrow the derived"),
        "{body}"
    );
}
