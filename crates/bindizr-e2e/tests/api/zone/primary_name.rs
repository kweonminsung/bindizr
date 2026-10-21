use domain::{
    base::{MessageBuilder, Rtype, UnknownRecordData},
    rdata::Soa,
};
use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{
    TestApp,
    dns::{fetch_exported_record_sets, parse_name},
    exchange_tcp,
};

/// Root MNAME survives creation, preview, update, history and wire/export encoding.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn root_primary_name_round_trips_through_management_and_dns() {
    let app = TestApp::start_local().await;
    app.create_secondary("loopback", "127.0.0.1").await;

    let name = app.zone_name("root-primary.example");

    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/zones",
                Some(json!({
                    "name": name, "mname": ".", "rname": "admin@example.net", "dry_run": dry_run
                })),
            )
            .await;

        assert_eq!(
            status,
            if dry_run {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            "{body}"
        );
        assert_eq!(body["zone"]["mname"], ".");
    }

    let sets = fetch_exported_record_sets(&app, &name).await;

    assert_eq!(sets[&(format!("{name}."), Rtype::NS)], [vec![0]]);
    assert_eq!(sets[&(format!("{name}."), Rtype::SOA)][0][0], 0);

    for rtype in [Rtype::SOA, Rtype::AXFR] {
        let mut question = MessageBuilder::new_vec().question();
        question.push((parse_name(&name).unwrap(), rtype)).unwrap();
        let wire = question.finish();
        let response = exchange_tcp(app.dns_port(), &wire).unwrap();
        let message = domain::base::Message::from_octets(response.as_slice()).unwrap();
        let soa = message
            .answer()
            .unwrap()
            .limit_to::<Soa<_>>()
            .next()
            .unwrap()
            .unwrap();

        assert!(soa.data().mname().is_root());

        if rtype == Rtype::AXFR {
            let ns = message
                .answer()
                .unwrap()
                .map(Result::unwrap)
                .find(|record| record.rtype() == Rtype::NS)
                .unwrap();

            assert_eq!(
                ns.to_record::<UnknownRecordData<_>>()
                    .unwrap()
                    .unwrap()
                    .data()
                    .data(),
                &[0]
            );
        }
    }

    let target_serial = app.read_zone_serial(&name).await;

    let path = format!("/zones/{name}");

    let (status, body) = app
        .send_request(Method::PUT, &path, Some(json!({"mname": "ns.example.net"})))
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let serial = app.read_zone_serial(&name).await;
    let (status, body) = app
        .send_request(
            Method::PUT,
            &path,
            Some(json!({"mname": ".", "dry_run": true})),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(app.read_zone_serial(&name).await, serial);

    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("{path}/versions/{target_serial}/rollback?dry_run={dry_run}"),
                None,
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["applied"], !dry_run);
    }

    let (status, body) = app.send_request(Method::GET, &path, None).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["zone"]["mname"], ".");

    for invalid in ["", ".."] {
        let (status, body) = app
            .send_request(Method::PUT, &path, Some(json!({"mname": invalid})))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
}

/// A root primary does not enable a preparation zone or permit managing the root zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn root_primary_name_preserves_zone_policy_and_import_creation() {
    let app = TestApp::start_local().await;
    let name = app.zone_name("root-preparation.example");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": name, "mname": ".", "rname": "admin@example.net", "apex_ns": false
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["zone"]["enabled"], false);
    assert!(app.list_records(&name).await.is_empty());

    let (status, body) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": ".", "mname": ".", "rname": "admin@example.net"
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let name = app.zone_name("root-import.example");
    let content = "@ IN SOA . admin.example.net. 1 3600 3600 604800 60\n@ IN NS .\n";

    for dry_run in [true, false] {
        let (status, body) = app
            .send_request(
                Method::POST,
                &format!("/zones/{name}/import"),
                Some(json!({
                    "content": content, "create": true, "dry_run": dry_run
                })),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["applied"], !dry_run);
    }

    let (status, body) = app
        .send_request(Method::GET, &format!("/zones/{name}"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["zone"]["mname"], ".");
}
