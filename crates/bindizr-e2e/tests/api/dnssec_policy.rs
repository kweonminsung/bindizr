use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_policy_create_read_update_delete() {
    let app = TestApp::start().await;
    let policy_name = format!("{}-strict", app.namespace());

    let (status, body) = app
        .request(
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
    // Omitted hold-downs take the built-in defaults.
    assert_eq!(policy["rollover_publish_holddown_secs"], 86400);
    assert_eq!(policy["rollover_retire_holddown_secs"], 172800);

    let (status, body) = app
        .request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_POLICY_CONFLICT");

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec_policy"]["algorithm"], "ed25519");

    // The seeded `default` policy is always listed alongside.
    let (status, body) = app.request(Method::GET, "/dnssec-policies", None).await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["dnssec_policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|policy| policy["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"default"), "{names:?}");
    assert!(names.contains(&policy_name.as_str()), "{names:?}");

    // An update edits only the fields given and keeps the rest.
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/dnssec-policies/{policy_name}"),
            Some(json!({ "signature_validity_days": 30, "rollover_retire_holddown_secs": 3600 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let policy = &body["dnssec_policy"];
    assert_eq!(policy["signature_validity_days"], 30);
    assert_eq!(policy["signature_refresh_days"], 7);
    assert_eq!(policy["rollover_retire_holddown_secs"], 3600);
    assert_eq!(policy["algorithm"], "ed25519");

    // A refresh window at least as long as the validity would re-sign on
    // every maintenance pass.
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/dnssec-policies/{policy_name}"),
            Some(json!({ "signature_refresh_days": 30 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "DNSSEC_POLICY_NOT_FOUND");

    // `default` is the by-name fallback of enable and import: editable, never deleted.
    let (status, body) = app
        .request(Method::DELETE, "/dnssec-policies/default", None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");
    let (status, body) = app
        .request(
            Method::PUT,
            "/dnssec-policies/default",
            Some(json!({ "signature_validity_days": 14 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["dnssec_policy"]["name"], "default");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dnssec_policy_in_use_cannot_be_deleted() {
    let app = TestApp::start().await;
    let policy_name = format!("{}-in-use", app.namespace());
    let (status, _) = app
        .request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": format!("{}-missing", app.namespace()) })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "DNSSEC_POLICY_NOT_FOUND");

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy": policy_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["dnssec"]["policy"]["name"], policy_name);

    let (status, body) = app
        .request(
            Method::DELETE,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "DNSSEC_POLICY_IN_USE");

    let (status, _) = app
        .request(Method::DELETE, &format!("/zones/{zone_name}/dnssec"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_moves_between_policies_and_rolls_algorithm() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let serial_before = body["dnssec"]["serial"].as_i64().unwrap();

    // A policy differing only in algorithm: the move double-signs the zone
    // through an algorithm rollover (RFC 6840, Section 5.11).
    let ed25519_policy = format!("{}-ed25519", app.namespace());
    let (status, _) = app
        .request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": ed25519_policy, "algorithm": "ed25519" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec/policy"),
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

    // The denial chain has no in-place transition, so a policy with the
    // other mode is refused.
    let nsec3_policy = format!("{}-nsec3", app.namespace());
    let (status, _) = app
        .request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": nsec3_policy, "denial": "nsec3" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec/policy"),
            Some(json!({ "policy": nsec3_policy })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_INPUT");

    // Moving to the same policy is a no-op that reports the current state.
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec/policy"),
            Some(json!({ "policy": ed25519_policy })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["dnssec"]["serial"].as_i64().unwrap(),
        serial_before + 1
    );
}
