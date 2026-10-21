use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{RECORD_ACTIONS, TestApp, TestAppOptions};

mod delegation;
mod rollover;

/// Verify the DNSSEC enable, status, re-sign, and disable lifecycle.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_supports_enable_sign_and_disable_lifecycle() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let serial_before = zone["serial"].as_i64().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body;

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
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_ALREADY_ENABLED");

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/dnssec"), None)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["enabled"], true);
    assert_eq!(body["keys"][0]["key_tag"], key_tag);

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

    // A DS secures a delegation, so the NS record set must exist first.
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
    assert_eq!(body["enabled"], false);

    // Absent values are null, never a missing key.
    assert!(body["policy"].is_null());
    assert!(body["keys"].as_array().unwrap().is_empty());

    let (status, body) = app
        .send_request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_NOT_ENABLED");
}

/// Verify DNSSEC enablement with NSEC3 and separate key roles.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_enable_supports_nsec3_with_split_keys() {
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
            Some(json!({ "policy_name": policy_name , "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);
    let dnssec = &body;

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
    let keys = body["keys"].as_array().unwrap();

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

/// Verify that DNSSEC enable requires `dnssec:manage`.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_enable_requires_dnssec_manage() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..TestAppOptions::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Grant the zone's records so the 403 proves the missing action, not
    // zone invisibility (which would read as 404).
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(
        &[
            "role",
            "grant",
            &scoped_name,
            "--zone",
            zone_name,
            "--actions",
            RECORD_ACTIONS,
        ],
        None,
    )
    .await;

    app.set_auth_token(scoped_token);

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "FORBIDDEN");
}
