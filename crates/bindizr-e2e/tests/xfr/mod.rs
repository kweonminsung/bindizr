//! Zone transfers as a secondary runs them: unsigned under the address ACL,
//! and signed under a TSIG key the way `primaries { addr key k; }` does.

use std::time::{Duration, Instant};

use domain::base::iana::Rcode;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use serial_test::serial;

use crate::common::{
    TestApp, TransferOutcome, axfr,
    dns::nsupdate::{SigningKey, create_tsig_key},
    wait_for_any_dns_record,
};

/// A bindizr whose transfer ACL admits the test's own loopback pull.
async fn transfer_app() -> TestApp {
    let app = TestApp::start_local().await;
    app.create_secondary("loopback", "127.0.0.1").await;
    app
}

/// Verify that an unsigned transfer is admitted only while its secondary is
/// registered and enabled.
#[tokio::test]
#[serial]
async fn an_unsigned_transfer_follows_the_secondary_registry() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Nobody is registered yet, so the address admits nothing.
    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    app.create_secondary("loopback", "127.0.0.1").await;
    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert!(outcome.records() >= 3);

    // Disabling keeps the row but closes the ACL from the next request on.
    app.run_cli_success(&["secondary", "update", "loopback", "--enabled", "false"])
        .await;
    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);

    app.run_cli_success(&["secondary", "update", "loopback", "--enabled", "true"])
        .await;
    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert!(outcome.records() >= 3);

    app.run_cli_success(&["secondary", "delete", "loopback"])
        .await;
    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);
}

/// Verify that an unsigned transfer still runs under the address acl.
#[tokio::test]
#[serial]
async fn an_unsigned_transfer_still_runs_under_the_address_acl() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert!(
        outcome.records() >= 3,
        "the zone carries its SOA twice plus NS"
    );
}

/// Verify that a signed transfer answers under the key that asked.
#[tokio::test]
#[serial]
async fn a_signed_transfer_answers_under_the_key_that_asked() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xfr-global-key", true).await;

    // `axfr` verifies every envelope's MAC, so an unsigned answer — which BIND
    // discards as "expected a TSIG" — fails here rather than passing silently.
    let outcome = axfr(app.dns_port(), zone_name, Some(&key)).expect("signed AXFR");
    assert!(outcome.records() >= 3);
}

/// Verify that a key transfers only the zones it is granted whole.
#[tokio::test]
#[serial]
async fn a_key_transfers_only_the_zones_it_is_granted_whole() {
    let app = transfer_app().await;
    let granted = app.create_test_zone().await;
    let granted = granted["name"].as_str().unwrap();
    let narrowed = app.zone_name("narrowed.example");
    app.create_zone_cli(&narrowed, "3600").await;
    let ungranted = app.zone_name("ungranted.example");
    app.create_zone_cli(&ungranted, "3600").await;

    let key = create_tsig_key(&app, "xfr-scoped-key", false).await;
    app.run_cli_success(&["tsig-key", "grant", &key.name, granted])
        .await;
    // A grant over part of a zone cannot hand the zone over whole.
    app.run_cli_success(&[
        "tsig-key",
        "grant",
        &key.name,
        &narrowed,
        "--pattern",
        "*.dyn",
    ])
    .await;

    let outcome = axfr(app.dns_port(), granted, Some(&key)).expect("granted AXFR");
    assert!(outcome.records() >= 3);

    for zone in [&narrowed, &ungranted] {
        let outcome = axfr(app.dns_port(), zone, Some(&key)).expect("AXFR");
        assert_eq!(outcome.refusal(), Rcode::REFUSED, "zone {zone}");
    }
}

/// Verify that a transfer only grant pulls the zone without changing it.
#[tokio::test]
#[serial]
async fn a_transfer_only_grant_pulls_the_zone_without_changing_it() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let key = create_tsig_key(&app, "xfr-read-only-key", false).await;
    app.run_cli_success(&["tsig-key", "grant", &key.name, zone_name, "--read-only"])
        .await;

    let outcome = axfr(app.dns_port(), zone_name, Some(&key)).expect("read-only AXFR");
    assert!(outcome.records() >= 3);

    // The same key must not be able to write what it just read.
    let rcode = crate::common::dns::nsupdate::send_signed_update(
        app.dns_port(),
        zone_name,
        &[],
        &[crate::common::dns::nsupdate::UpdateRecord::AddA {
            name: format!("www.{zone_name}."),
            ttl: 300,
            addr: "192.0.2.80".to_string(),
        }],
        &key,
    )
    .expect("signed update");
    assert_eq!(rcode, Rcode::REFUSED);
}

/// Verify that an unknown key is refused rather than falling back to the address.
#[tokio::test]
#[serial]
async fn an_unknown_key_is_refused_rather_than_falling_back_to_the_address() {
    let app = transfer_app().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // The address would have been allowed; signing with a key bindizr does not
    // hold must not be a way around the check.
    let stranger = SigningKey {
        name: "stranger-key".to_string(),
        secret: "c3RyYW5nZXItc2VjcmV0LW1hdGVyaWFsLWZvci10ZXN0cw==".to_string(),
    };
    let outcome = axfr(app.dns_port(), zone_name, Some(&stranger));
    assert!(
        outcome.is_err() || matches!(outcome, Ok(TransferOutcome::Refused(_))),
        "an unknown key was accepted: {outcome:?}"
    );
}

const DNSKEY: u16 = 48;
const RRSIG: u16 = 46;
const NSEC3PARAM: u16 = 51;
const CDS: u16 = 59;

/// Verify that signed zone propagates DNSSEC records and signed IXFR.
#[tokio::test]
#[serial]
async fn signed_zone_propagates_dnssec_records_and_signed_ixfr() {
    let app = TestApp::start().await;
    // Only the compose stack runs BIND9 secondaries to observe.
    if !app.has_dns_secondaries() {
        return;
    }

    // Phase 1: an unsigned zone with one A record, propagated to both
    // secondaries by the harness's post-mutation DNS verification.
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap().to_string();
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

    // Phase 2: enable DNSSEC.
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Phase 3: the signed view reaches both secondaries. Explicit-type
    // queries return DNSSEC records without the DO bit.
    for port in app.dns_secondary_ports() {
        wait_for_any_dns_record(*port, &zone_name, DNSKEY).await;
        wait_for_any_dns_record(*port, &zone_name, RRSIG).await;
    }

    // Phase 4: a record mutation on the signed zone re-signs in the same
    // transaction; the harness's DNS verification waits for the new A record
    // on both secondaries, so this exercises the signed IXFR delta.
    let serial_before = app.read_zone_serial(&zone_name).await;
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "api",
                "type": "A",
                "value": "192.0.2.11",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(app.read_zone_serial(&zone_name).await, serial_before + 1);

    // Phase 5: both secondaries converge on the bumped serial.
    let mut attempts = 0;
    loop {
        let (_, body) = app
            .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
            .await;
        let all_in_sync = body["secondaries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|secondary| secondary["status"] == "in_sync");
        if all_in_sync {
            break;
        }
        attempts += 1;
        assert!(attempts < 60, "secondaries never reached in_sync: {body}");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Verify that NSEC3 zone propagates nsec3param and CDS.
#[tokio::test]
#[serial]
async fn nsec3_zone_propagates_nsec3param_and_cds() {
    let app = TestApp::start().await;
    // Only the compose stack runs BIND9 secondaries to observe.
    if !app.has_dns_secondaries() {
        return;
    }

    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap().to_string();
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

    let policy_name = format!("{}-nsec3", app.namespace());
    let (status, _) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name, "denial": "nsec3" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "policy_name": policy_name , "parent_ns_addrs": ["127.0.0.1:9"]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // NSEC3PARAM at the apex shows the NSEC3 denial plane transferred; CDS
    // (RFC 7344) shows the derived key record set plane did too.
    for port in app.dns_secondary_ports() {
        wait_for_any_dns_record(*port, &zone_name, NSEC3PARAM).await;
        wait_for_any_dns_record(*port, &zone_name, CDS).await;
    }
}

/// Read the loopback secondary's transfers until the summary counts
/// `expected` under `field`, or give up after a few seconds and hand back
/// what it says. The daemon saves a transfer after answering it, so a read
/// right behind the client can still see the row about to be replaced.
async fn wait_for_transfer_summary(app: &TestApp, field: &str, expected: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (status, body) = app
            .send_request(Method::GET, "/secondaries/loopback/transfers", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        if body["summary"][field] == expected || Instant::now() > deadline {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Verify that the transfers Bindizr served a secondary, and the refusals
/// before it was registered, are read back per zone and beside the zone's
/// status.
#[tokio::test]
#[serial]
async fn the_transfers_served_a_secondary_are_read_back() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Refused while unregistered; rows key by address, so registering it
    // afterwards reveals the refusal.
    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert_eq!(outcome.refusal(), Rcode::REFUSED);
    app.create_secondary("loopback", "127.0.0.1").await;

    let body = wait_for_transfer_summary(&app, "refused", 1).await;
    assert_eq!(body["summary"]["zones"], 1, "{body}");
    assert_eq!(body["summary"]["refused"], 1, "{body}");
    assert_eq!(body["transfers"][0]["zone_name"], zone_name);
    assert_eq!(body["transfers"][0]["kind"], "axfr");
    assert_eq!(body["transfers"][0]["result"], "refused");
    assert!(body["transfers"][0]["serial"].is_null(), "{body}");
    assert!(!body["transfers"][0]["error"].is_null(), "{body}");

    let outcome = axfr(app.dns_port(), zone_name, None).expect("AXFR");
    assert!(outcome.records() >= 3);

    let body = wait_for_transfer_summary(&app, "axfr", 1).await;
    assert_eq!(body["summary"]["zones"], 1, "{body}");
    assert_eq!(body["summary"]["axfr"], 1, "{body}");
    assert_eq!(body["summary"]["refused"], 0, "{body}");
    assert_eq!(body["summary"]["failed"], 0, "{body}");
    assert_eq!(body["transfers"][0]["kind"], "axfr");
    assert_eq!(body["transfers"][0]["result"], "ok");
    assert_eq!(body["transfers"][0]["incremental"], false);
    assert_eq!(body["transfers"][0]["serial"], zone["serial"], "{body}");
    assert!(body["transfers"][0]["error"].is_null(), "{body}");
    assert_eq!(body["transfers"][0]["address"], "127.0.0.1");

    // A zone filter for another zone leaves the summary and empties the list.
    let (status, body) = app
        .send_request(
            Method::GET,
            "/secondaries/loopback/transfers?zone_name=other.example",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["summary"]["zones"], 1, "{body}");
    assert_eq!(
        body["transfers"].as_array().map(Vec::len),
        Some(0),
        "{body}"
    );

    // The filter is a zone name: the absolute spelling selects the same
    // rows, and one that is no name is refused.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/secondaries/loopback/transfers?zone_name={zone_name}."),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["transfers"][0]["zone_name"], zone_name, "{body}");
    let (status, body) = app
        .send_request(
            Method::GET,
            "/secondaries/loopback/transfers?zone_name=*",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_ZONE_FIELD", "{body}");

    // The zone's status carries the same transfer beside the probe, which
    // finds nothing listening on the registered address.
    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/status"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["secondaries"][0]["last_transfer"]["kind"], "axfr",
        "{body}"
    );
    assert_eq!(
        body["secondaries"][0]["last_transfer"]["serial"], zone["serial"],
        "{body}"
    );

    let listed = app
        .run_cli_success(&["secondary", "transfers", "loopback"])
        .await;
    assert!(
        listed.contains(zone_name) && listed.contains("AXFR") && listed.contains("1 zones:"),
        "{listed}"
    );
    // The check fails, since nothing answers on the registered address, but
    // still reports the transfers.
    let checked = app.run_cli(&["secondary", "check", "loopback"]).await;
    let stdout = String::from_utf8_lossy(&checked.stdout);
    assert!(stdout.contains("Transfers: 1 zones:"), "{stdout}");
}
