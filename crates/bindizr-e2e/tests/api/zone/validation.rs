use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

/// Verify that a rename keeps every record inside the wire limit.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_rename_keeps_every_record_inside_the_wire_limit() {
    let app = TestApp::start().await;
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": "a.co",
                "mname": "ns.a.co",
                "rname": "admin@a.co",
                "default_ttl": 3600
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // 249 wire octets under `a.co`, six short of the limit; the seventeen
    // more of `rename-length.example` make it 266.
    let owner = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50),
    ]
    .join(".");
    let (status, body) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": owner,
                "record_type": "A",
                "value": "192.0.2.1",
                "zone_name": "a.co"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The record was validated under `a.co`; the rename must re-check it, or
    // the zone would commit a name its transfers cannot encode.
    let (status, body) = app
        .request(
            Method::PUT,
            "/zones/a.co",
            Some(json!({ "name": "rename-length.example" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("bytes or fewer"), "{body}");
    let (status, _) = app.request(Method::GET, "/zones/a.co", None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(Method::PUT, "/zones/a.co", Some(json!({ "name": "b.co" })))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Verify that a rollback keeps every restored record inside the wire limit.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_rollback_keeps_every_restored_record_inside_the_wire_limit() {
    let app = TestApp::start().await;
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": "c.co",
                "mname": "ns.c.co",
                "rname": "admin@c.co",
                "default_ttl": 3600
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let owner = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(50),
    ]
    .join(".");
    let (status, body) = app
        .request(
            Method::POST,
            "/records",
            Some(json!({
                "name": owner,
                "record_type": "A",
                "value": "192.0.2.1",
                "zone_name": "c.co"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let record_id = body["record"]["id"].as_i64().unwrap();
    let (_, zone_at_target) = app.request(Method::GET, "/zones/c.co", None).await;
    let target_serial = zone_at_target["zone"]["serial"].as_i64().unwrap();

    // With the long name gone the rename passes; the history still holds it.
    let (status, _) = app
        .request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert!(status.is_success(), "{status}");
    let (status, body) = app
        .request(
            Method::PUT,
            "/zones/c.co",
            Some(json!({ "name": "rollback-length.example" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Restoring that serial would bring the name back under a zone it no
    // longer fits, so the rollback is refused whole.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/rollback-length.example/versions/{target_serial}/rollback"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("bytes or fewer"), "{body}");
}

/// Verify zone-field validation and normalization.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_validate_and_normalize() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("test.example.com");
    let second_zone_name = app.zone_name("second.example.com");

    // The second entry is already in SOA-mailbox form: the API accepts email
    // addresses only and must not pass a mailbox through untranslated.
    for invalid_rname in [
        json!({
            "name": "invalid-rname.com",
            "mname": "ns1.invalid-rname.com",
            "rname": "admin@@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "soa-mailbox.com",
            "mname": "ns1.soa-mailbox.com",
            "rname": "hostmaster.soa-mailbox.com.",
            "default_ttl": 3600
        }),
    ] {
        let (status, _) = app
            .request(Method::POST, "/zones", Some(invalid_rname))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let create_zone_request = json!({
        "name": format!(" {}. ", zone_name.to_ascii_uppercase()),
        "mname": format!("NS1.{}.", zone_name.to_ascii_uppercase()),
        "rname": "Host.Master@Example.Com.",
        "default_ttl": 3600
    });
    let (status, body) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], zone_name);
    assert_eq!(body["zone"]["mname"], format!("ns1.{zone_name}"));
    // Only the domain part of the email is case-normalized; the local part is
    // case-significant and must be preserved.
    assert_eq!(body["zone"]["rname"], "Host.Master@example.com");

    let duplicate_zone_request = json!({
        "name": format!("{zone_name}."),
        "mname": format!("ns2.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, _) = app
        .request(Method::POST, "/zones", Some(duplicate_zone_request))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let second_zone = json!({
        "name": second_zone_name,
        "mname": format!("ns1.{second_zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, _) = app.request(Method::POST, "/zones", Some(second_zone)).await;
    assert_eq!(status, StatusCode::CREATED);

    let normalize_update = json!({
        "name": format!(" {}. ", zone_name.to_ascii_uppercase()),
        "mname": format!("NS1.{}.", zone_name.to_ascii_uppercase()),
        "rname": "Host.Master@Example.Com.",
        "default_ttl": 7200
    });
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(normalize_update),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], zone_name);
    assert_eq!(body["zone"]["mname"], format!("ns1.{zone_name}"));
    assert_eq!(body["zone"]["rname"], "Host.Master@example.com");

    let rename_onto_existing = json!({
        "name": format!("{}.", second_zone_name.to_ascii_uppercase()),
        "mname": format!("ns1.{zone_name}"),
        "rname": "hostmaster@example.com",
        "default_ttl": 3600
    });
    let (status, _) = app
        .request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(rename_onto_existing),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    for invalid_update in [
        json!({
            "name": format!("{}..example.com", app.namespace()),
            "mname": format!("ns1.{zone_name}"),
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": zone_name,
            "mname": format!("ns1.{zone_name}"),
            "rname": "hostmaster@example.com",
            "default_ttl": 0
        }),
    ] {
        let (status, _) = app
            .request(
                Method::PUT,
                &format!("/zones/{zone_name}"),
                Some(invalid_update),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

/// Verify rejection of invalid zone names and TTLs.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_reject_invalid_name_and_ttl() {
    let app = TestApp::start().await;

    for invalid_zone in [
        json!({
            "name": "*.example.com",
            "mname": "ns1.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": ".",
            "mname": "ns.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "_tcp.example.com",
            "mname": "ns._tcp.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "test..example.com",
            "mname": "ns.test.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "-test.example.com",
            "mname": "ns.-test.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": "low-ttl.example.com",
            "mname": "ns.low-ttl.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 0
        }),
        json!({
            "name": "high-ttl.example.com",
            "mname": "ns.high-ttl.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 604801
        }),
    ] {
        let (status, _) = app
            .request(Method::POST, "/zones", Some(invalid_zone))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // These look suspicious but are legal: an mname outside the zone
    // (out-of-bailiwick) and an NS name unrelated to the zone.
    for valid_zone in [
        json!({
            "name": app.zone_name("bailiwick.example.com"),
            "mname": "ns.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
        json!({
            "name": app.zone_name("bad-ns.example.com"),
            "mname": "badtest.example.com",
            "rname": "hostmaster@example.com",
            "default_ttl": 3600
        }),
    ] {
        let (status, _) = app.request(Method::POST, "/zones", Some(valid_zone)).await;
        assert_eq!(status, StatusCode::CREATED);
    }
}
