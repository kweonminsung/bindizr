//! Zone transfers as a secondary runs them: unsigned under the address ACL,
//! and signed under a TSIG key the way `primaries { addr key k; }` does.

use domain::base::iana::Rcode;
use reqwest::{Method, StatusCode};
use serde_json::json;
use serial_test::serial;

use crate::common::{
    TestApp, TestAppOptions, TransferOutcome, axfr,
    dns::nsupdate::{SigningKey, create_tsig_key},
    wait_for_any_dns_record,
};

/// A bindizr whose transfer ACL admits the test's own loopback pull.
async fn transfer_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        secondary_addrs: "127.0.0.1".to_string(),
        ..TestAppOptions::default()
    })
    .await
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
        &[crate::common::dns::nsupdate::UpdateRr::AddA {
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
            Some(json!({ "parent_ns_addrs": "127.0.0.1:9"})),
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
            Some(json!({ "policy": policy_name , "parent_ns_addrs": "127.0.0.1:9"})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // NSEC3PARAM at the apex shows the NSEC3 denial plane transferred; CDS
    // (RFC 7344) shows the derived key-RRset plane did too.
    for port in app.dns_secondary_ports() {
        wait_for_any_dns_record(*port, &zone_name, NSEC3PARAM).await;
        wait_for_any_dns_record(*port, &zone_name, CDS).await;
    }
}
