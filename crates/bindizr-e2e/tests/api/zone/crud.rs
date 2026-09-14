use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_read_update_delete() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("test.com");
    let updated_zone_name = app.zone_name("updated-test.com");

    let create_zone_request = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "admin@test.com",
        "default_ttl": 3600,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });

    let (status, body) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let created_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(created_zone_name, zone_name);

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{created_zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], zone_name);

    let update_zone_request = json!({
        "name": updated_zone_name,
        "mname": "ns2.external-dns.net",
        "rname": "admin@updated-test.com",
        "default_ttl": 7200,
        "refresh": 14400,
        "retry": 7200,
        "expire": 1209600,
        "minimum_ttl": 172800
    });

    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{created_zone_name}"),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let actual_updated_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(actual_updated_zone_name, updated_zone_name);

    // A partial update keeps every omitted field.
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{actual_updated_zone_name}"),
            Some(json!({ "default_ttl": 300 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["default_ttl"], 300);
    assert_eq!(body["zone"]["mname"], "ns2.external-dns.net");
    assert_eq!(body["zone"]["rname"], "admin@updated-test.com");
    assert_eq!(body["zone"]["refresh"], 14400);

    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/zones/{actual_updated_zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(
            Method::GET,
            &format!("/zones/{actual_updated_zone_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_seed_and_reject_out_of_range_serial() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("seeded-serial.example.com");

    // Secondaries compare serials per RFC 1982, so a takeover has to continue
    // from the previous primary's serial instead of restarting at 1.
    let seeded_zone = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600,
        "serial": 2026072501i64
    });
    let (status, body) = app.request(Method::POST, "/zones", Some(seeded_zone)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["serial"], 2026072501i64);

    let update_zone_request = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 7200
    });
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["serial"], 2026072502i64);

    // Past MAX_INITIAL_SERIAL (i32::MAX - 10_000_000) the counter would
    // saturate while the zone is still in use.
    for out_of_range_serial in [0i64, -1, 2_137_483_648, i32::MAX as i64] {
        let out_of_range_zone = json!({
            "name": app.zone_name("out-of-range-serial.example.com"),
            "mname": "ns1.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600,
            "serial": out_of_range_serial
        });
        let (status, _) = app
            .request(Method::POST, "/zones", Some(out_of_range_zone))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_auto_serial_starts_at_one_and_update_rejects_explicit_serial() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("counter.example");

    let request = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@counter.example",
        "default_ttl": 3600
    });
    let (status, body) = app.request(Method::POST, "/zones", Some(request)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["serial"].as_i64().unwrap(), 1);

    let record = json!({
        "name": "www", "record_type": "A", "value": "192.0.2.70",
        "ttl": 300, "zone_name": zone_name
    });
    let (status, _) = app.request(Method::POST, "/records", Some(record)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, after) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(after["zone"]["serial"].as_i64().unwrap(), 2);

    let update_with_serial = json!({
        "name": zone_name,
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@counter.example",
        "default_ttl": 3600,
        "serial": 99
    });
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(update_with_serial),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("managed automatically")
    );
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn apex_rows_render_and_update_through_their_presentation_name() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, detail) = app
        .request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/{}", zone["serial"]),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = detail["records"]
        .as_array()
        .expect("version records")
        .iter()
        .map(|record| record["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, ["@"], "apex row did not render as the apex");

    let records = app.list_records(zone_name).await;
    let ns = records
        .iter()
        .find(|record| record["record_type"] == "NS")
        .expect("apex NS row");
    for spelling in ["@", zone_name] {
        let (status, body) = app
            .request(
                Method::PUT,
                &format!("/records/{}", ns["id"].as_i64().unwrap()),
                Some(json!({
                    "name": spelling,
                    "record_type": "NS",
                    "value": ns["value"],
                    "default_ttl": 1200,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{spelling}: {body}");
    }
}
