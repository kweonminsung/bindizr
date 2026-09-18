use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify DNSSEC policy creation, retrieval, update, and deletion.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_policy_create_read_update_delete() {
    let app = TestApp::start().await;
    let policy_name = format!("{}-strict", app.namespace());

    let (status, body) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({
                "name": policy_name,
                "algorithm": "ed25519",
                "denial": "nsec3",
                "signature_validity_days": 21,
                "signature_refresh_days": 7,
                "zsk_lifetime_days": 90,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let policy = &body["dnssec_policy"];
    assert_eq!(policy["name"], policy_name);
    assert_eq!(policy["algorithm"], "ed25519");
    assert_eq!(policy["denial"], "nsec3");
    assert_eq!(policy["split_keys"], false);
    assert_eq!(policy["signature_validity_days"], 21);
    assert_eq!(policy["signature_refresh_days"], 7);
    assert_eq!(policy["zsk_lifetime_days"], 90);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_POLICY_CONFLICT");

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec_policy"]["algorithm"], "ed25519");

    // The seeded `default` policy is always listed alongside.
    let (status, body) = app
        .send_request(Method::GET, "/dnssec-policies", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|policy| policy["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"default"), "{names:?}");
    assert!(names.contains(&policy_name.as_str()), "{names:?}");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/dnssec-policies/{policy_name}"),
            Some(json!({ "signature_validity_days": 30 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let policy = &body["dnssec_policy"];
    assert_eq!(policy["signature_validity_days"], 30);
    assert_eq!(policy["signature_refresh_days"], 7);
    assert_eq!(policy["algorithm"], "ed25519");

    // A refresh window at least as long as the validity would re-sign on
    // every scheduler pass.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/dnssec-policies/{policy_name}"),
            Some(json!({ "signature_refresh_days": 30 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "DNSSEC_POLICY_NOT_FOUND");

    // `default` is the by-name fallback of enable and import: editable, never deleted.
    let (status, body) = app
        .send_request(Method::DELETE, "/dnssec-policies/default", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
    let (status, body) = app
        .send_request(
            Method::PUT,
            "/dnssec-policies/default",
            Some(json!({ "signature_validity_days": 14 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec_policy"]["name"], "default");
}

/// Verify an assigned DNSSEC policy becomes deletable after DNSSEC is disabled.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_policy_in_use_cannot_be_deleted() {
    let app = TestApp::start().await;
    let policy_name = format!("{}-in-use", app.namespace());
    let (status, _) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A missing policy cannot establish the zone's signing configuration.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": format!("{}-missing", app.namespace()) , "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "DNSSEC_POLICY_NOT_FOUND");

    // Once the zone uses the policy, deletion must respect that reference.
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": policy_name , "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["dnssec"]["policy"]["name"], policy_name);

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_POLICY_IN_USE");

    // Release the zone's policy reference by disabling DNSSEC, then delete the policy.
    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/zones/{zone_name}/dnssec?skip_ds_check=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Verify that zone moves between policies and rolls algorithm.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_moves_between_policies_and_rolls_algorithm() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let serial_before = body["dnssec"]["serial"].as_i64().unwrap();

    // A policy differing only in algorithm: the move double-signs the zone
    // through an algorithm rollover (RFC 6840, Section 5.11).
    let ed25519_policy = format!("{}-ed25519", app.namespace());
    let (status, _) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": ed25519_policy, "algorithm": "ed25519" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": ed25519_policy })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let dnssec = &body["dnssec"];
    assert_eq!(dnssec["policy"]["name"], ed25519_policy);
    let keys = dnssec["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let published = keys
        .iter()
        .find(|key| key["state"] == "published")
        .expect("the move pre-publishes a replacement of the new algorithm");
    assert_eq!(published["algorithm"], "ed25519");
    let active = keys
        .iter()
        .find(|key| key["state"] == "active")
        .expect("the old key keeps signing during the rollover");
    assert_eq!(active["algorithm"], "ecdsap256sha256");
    assert_eq!(dnssec["serial"].as_i64().unwrap(), serial_before + 1);

    // Moving to the same policy is a no-op that reports the current state.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": ed25519_policy })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["dnssec"]["serial"].as_i64().unwrap(),
        serial_before + 1
    );
}

/// Verify that zone moves between denial chains without going insecure.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_moves_between_denial_chains_without_going_insecure() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let nsec_policy = format!("{}-nsec", app.namespace());
    let (status, _) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": nsec_policy, "denial": "nsec" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": nsec_policy, "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let mut serial = body["dnssec"]["serial"].as_i64().unwrap();

    let denial_types = async |app: &TestApp| -> Vec<String> {
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&signed=true&limit=1000"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut types: Vec<String> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["type"].as_str().unwrap().to_string())
            .filter(|record_type| record_type.starts_with("NSEC"))
            .collect();
        types.sort();
        types.dedup();
        types
    };
    assert_eq!(denial_types(&app).await, ["NSEC"]);

    // The zone signs with ECDSA P-256, which is NSEC3-capable (RFC 5155,
    // Section 2), so the chain is replaced under one serial with no key roll.
    let nsec3_policy = format!("{}-nsec3", app.namespace());
    let (status, _) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": nsec3_policy, "denial": "nsec3" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": nsec3_policy })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["dnssec"]["keys"].as_array().unwrap().len(), 1);
    assert_eq!(body["dnssec"]["serial"].as_i64().unwrap(), serial + 1);
    serial += 1;
    assert_eq!(denial_types(&app).await, ["NSEC3", "NSEC3PARAM"]);

    // And back: neither direction needs a key roll.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": nsec_policy })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["dnssec"]["serial"].as_i64().unwrap(), serial + 1);
    assert_eq!(denial_types(&app).await, ["NSEC"]);
}
