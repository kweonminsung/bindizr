use domain::base::iana::{Rcode, Rtype};
use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::dns::nsupdate::UpdateRecord;
use crate::common::dns::tsig::KeyRole;
use crate::common::dns::{nsupdate, tsig};
use crate::common::{TestApp, dns};

/// Verify that canonical targets cannot sit below a DNAME, whichever record arrives first.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dname_targets_reject_both_creation_orders_and_previews() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    for record_type in ["NS", "MX", "PTR", "SRV"] {
        for dname_first in [true, false] {
            let redirect = format!(
                "redirect-{}-{dname_first}",
                record_type.to_ascii_lowercase()
            );
            let target = format!("host.{redirect}.{zone_name}.");
            let target = if record_type == "SRV" {
                format!("0 443 {target}")
            } else {
                target
            };
            let alias = json!({ "zone_name": zone_name, "name": redirect, "type": "DNAME", "value": "elsewhere.example.net." });
            let priority = matches!(record_type, "MX" | "SRV").then_some(10);
            let reference = json!({ "zone_name": zone_name, "name": format!("reference-{redirect}"), "type": record_type, "value": target, "priority": priority });
            let (first, second) = if dname_first {
                (alias, reference)
            } else {
                (reference, alias)
            };

            let (status, body) = app
                .send_request(Method::POST, "/records", Some(first))
                .await;

            assert_eq!(status, StatusCode::CREATED, "{body}");

            let base_serial = app.read_zone_serial(zone_name).await;
            let before = app.list_records(zone_name).await;

            for dry_run in [true, false] {
                let mut request = second.clone();
                request["dry_run"] = json!(dry_run);

                let (status, body) = app
                    .send_request(Method::POST, "/records", Some(request))
                    .await;

                assert_eq!(
                    status,
                    StatusCode::CONFLICT,
                    "{record_type}, DNAME first={dname_first}: {body}"
                );
                assert_eq!(body["code"], "RECORD_CONFLICT");
                assert_eq!(app.read_zone_serial(zone_name).await, base_serial);
                assert_eq!(app.list_records(zone_name).await, before);
            }
        }
    }
}

/// Verify that DNAME owners, escaped labels, external names and data below a cut are distinct.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dname_targets_respect_label_and_delegation_boundaries() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records/bulk",
            Some(json!({
                "zone_name": zone_name,
                "records": [
                    { "name": "redirect", "type": "DNAME", "value": "elsewhere.example.net." },
                    { "name": "delegated", "type": "NS", "value": "ns.example.net." },
                    { "name": "redirect.delegated", "type": "DNAME", "value": "elsewhere.example.net." }
                ]
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let delegation_record_id = body["records"][1]["id"].as_i64().unwrap();

    for target in [
        format!("redirect.{zone_name}."),
        format!(r"host\046redirect.{zone_name}."),
        format!("host.redirect.delegated.{zone_name}."),
        "host.redirect.example.net.".to_string(),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "zone_name": zone_name, "name": "@", "type": "MX", "priority": 10, "value": target
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{target}: {body}");
    }

    for (owner, record_type, value, priority) in [
        ("null-mail", "MX", ".", Some(0)),
        ("no-service", "SRV", "0 0 .", Some(0)),
        ("root-ns", "NS", ".", None),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(json!({
                    "zone_name": zone_name, "name": owner, "type": record_type, "priority": priority, "value": value
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // Removing the cut would make its DNAME authoritative over a stored target.
    let base_serial = app.read_zone_serial(zone_name).await;

    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::DELETE,
                &format!("/records/{delegation_record_id}?dry_run={dry_run}"),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(app.read_zone_serial(zone_name).await, base_serial);
    }
}

/// Verify that bulk, import, replacement and ordered UPDATE validate the final state atomically.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn dname_targets_validate_mutation_candidates_atomically() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let key = tsig::create_tsig_key(&app, "dname-targets", KeyRole::Admin).await;
    let base_serial = app.read_zone_serial(zone_name).await;
    let before = app.list_records(zone_name).await;

    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records/bulk",
                Some(json!({
                    "zone_name": zone_name, "dry_run": dry_run,
                    "records": [
                        { "name": "redirect", "type": "DNAME", "value": "elsewhere.example.net." },
                        { "name": "mail", "type": "MX", "priority": 10, "value": format!("host.redirect.{zone_name}.") }
                    ]
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let content = format!(
            "redirect IN DNAME elsewhere.example.net.\nmail IN MX 10 host.redirect.{zone_name}.\n"
        );

        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{zone_name}/import"),
                Some(json!({
                    "content": content, "dry_run": dry_run
                })),
            )
            .await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["applied"], false);
        assert_eq!(app.read_zone_serial(zone_name).await, base_serial);
        assert_eq!(app.list_records(zone_name).await, before);
    }

    let target = dns::parse_name(&format!("host.redirect.{zone_name}."))
        .unwrap()
        .as_slice()
        .to_vec();
    let mut mx = vec![0, 10];
    mx.extend_from_slice(&target);
    let updates = [
        UpdateRecord::AddRecord {
            name: format!("redirect.{zone_name}."),
            rtype: Rtype::DNAME,
            ttl: 300,
            rdata: vec![0],
        },
        UpdateRecord::AddRecord {
            name: format!("mail.{zone_name}."),
            rtype: Rtype::MX,
            ttl: 300,
            rdata: mx,
        },
    ];

    assert_eq!(
        nsupdate::send_update_tcp(app.dns_port(), zone_name, &[], &updates, Some(&key)).unwrap(),
        Rcode::REFUSED
    );
    assert_eq!(app.read_zone_serial(zone_name).await, base_serial);
    assert_eq!(app.list_records(zone_name).await, before);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "zone_name": zone_name, "name": "redirect", "type": "DNAME", "value": "."
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "zone_name": zone_name, "name": "mail", "type": "MX", "priority": 10, "value": format!("redirect.{zone_name}.")
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let mx_record_id = body["record"]["id"].as_i64().unwrap();

    let base_serial = app.read_zone_serial(zone_name).await;

    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::PUT,
                &format!("/records/{mx_record_id}"),
                Some(json!({
                    "value": format!("host.redirect.{zone_name}."), "dry_run": dry_run
                })),
            )
            .await;

        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(app.read_zone_serial(zone_name).await, base_serial);
    }

    // Replacing the zone removes the DNAME before the target constraint is checked.
    let content = format!("@ IN NS ns.example.net.\nmail IN MX 10 host.redirect.{zone_name}.\n");

    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{zone_name}/import"),
                Some(json!({
                    "content": content, "mode": "replace", "dry_run": dry_run
                })),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["applied"], !dry_run);
    }
}
