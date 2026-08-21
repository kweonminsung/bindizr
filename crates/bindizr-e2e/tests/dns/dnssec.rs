use reqwest::{Method, StatusCode};
use serde_json::json;
use serial_test::serial;

use crate::common::{TestApp, wait_for_any_dns_record};

const DNSKEY: u16 = 48;
const RRSIG: u16 = 46;
const NSEC3PARAM: u16 = 51;
const CDS: u16 = 59;

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

    // Phase 2: enable DNSSEC.
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({})),
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
    let serial_before = app.zone_serial(&zone_name).await;
    let (status, _) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": "api",
                "record_type": "A",
                "value": "192.0.2.11",
                "zone_name": zone_name,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(app.zone_serial(&zone_name).await, serial_before + 1);

    // Phase 5: both secondaries converge on the bumped serial.
    let mut attempts = 0;
    loop {
        let (_, body) = app
            .request(Method::GET, &format!("/zones/{zone_name}/status"), None)
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
            Some(json!({ "denial": "nsec3" })),
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
