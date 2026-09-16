//! Zone transfers as a secondary runs them: unsigned under the address ACL,
//! and signed under a TSIG key the way `primaries { addr key k; }` does.

use domain::base::iana::Rcode;
use serial_test::serial;

use crate::common::{TestApp, TestAppOptions, TransferOutcome, axfr, nsupdate::SigningKey};

/// A bindizr whose transfer ACL admits the test's own loopback pull.
async fn transfer_app() -> TestApp {
    TestApp::start_with_options(TestAppOptions {
        secondary_addrs: "127.0.0.1".to_string(),
        ..TestAppOptions::default()
    })
    .await
}

/// Create a TSIG key fixture with the requested global access.
async fn create_key(app: &TestApp, name: &str, global: bool) -> SigningKey {
    let mut args = vec!["tsig-key", "create", name];
    if global {
        args.push("--global");
    }
    app.run_cli_success(&args).await;
    let fetched = app
        .run_cli_success(&["tsig-key", "get", name, "--output", "json"])
        .await;
    let fetched: serde_json::Value =
        serde_json::from_str(&fetched).expect("tsig-key get did not print JSON");
    SigningKey {
        name: name.to_string(),
        secret: fetched["secret"]
            .as_str()
            .expect("tsig-key get prints the secret")
            .to_string(),
    }
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
    let key = create_key(&app, "xfr-global-key", true).await;

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

    let key = create_key(&app, "xfr-scoped-key", false).await;
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
    let key = create_key(&app, "xfr-read-only-key", false).await;
    app.run_cli_success(&["tsig-key", "grant", &key.name, zone_name, "--read-only"])
        .await;

    let outcome = axfr(app.dns_port(), zone_name, Some(&key)).expect("read-only AXFR");
    assert!(outcome.records() >= 3);

    // The same key must not be able to write what it just read.
    let rcode = crate::common::nsupdate::send_signed_update(
        app.dns_port(),
        zone_name,
        &[],
        &[crate::common::nsupdate::UpdateRr::AddA {
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
