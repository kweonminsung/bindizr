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
        "primary_ns": format!("ns1.{zone_name}"),
        "admin_email": "admin@test.com",
        "ttl": 3600,
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
        "primary_ns": "ns2.external-dns.net",
        "admin_email": "admin@updated-test.com",
        "ttl": 7200,
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
async fn zone_filter_and_paginate() {
    let app = TestApp::start().await;
    app.create_test_zone().await;
    let filtered_zone_name = app.zone_name("filtered.net");

    let create_zone_request = json!({
        "name": filtered_zone_name,
        "primary_ns": format!("ns1.{filtered_zone_name}"),
        "admin_email": "admin@filtered.net",
        "ttl": 7200,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });
    let (status, _) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = app
        .request(
            Method::GET,
            &format!(
                "/zones?search={}&min_ttl=7000&max_ttl=8000",
                app.namespace()
            ),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], filtered_zone_name);

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/zones?search={}&limit=1&offset=1", app.namespace()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], filtered_zone_name);
    assert_eq!(body["pagination"]["total"], 2);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 1);

    let (status, _) = app.request(Method::GET, "/zones?limit=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_validate_and_normalize() {
    let app = TestApp::start().await;
    let zone_name = app.zone_name("test.example.com");
    let second_zone_name = app.zone_name("second.example.com");

    for invalid_admin_email in [
        json!({
            "name": "invalid-admin-email.com",
            "primary_ns": "ns1.invalid-admin-email.com",
            "admin_email": "admin@@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "soa-mailbox.com",
            "primary_ns": "ns1.soa-mailbox.com",
            "admin_email": "hostmaster.soa-mailbox.com.",
            "ttl": 3600
        }),
    ] {
        let (status, _) = app
            .request(Method::POST, "/zones", Some(invalid_admin_email))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let create_zone_request = json!({
        "name": format!(" {}. ", zone_name.to_ascii_uppercase()),
        "primary_ns": format!("NS1.{}.", zone_name.to_ascii_uppercase()),
        "admin_email": "Host.Master@Example.Com.",
        "ttl": 3600
    });
    let (status, body) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], zone_name);
    assert_eq!(body["zone"]["primary_ns"], format!("ns1.{zone_name}"));
    assert_eq!(body["zone"]["admin_email"], "Host.Master@example.com");

    let duplicate_zone_request = json!({
        "name": format!("{zone_name}."),
        "primary_ns": format!("ns2.{zone_name}"),
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = app
        .request(Method::POST, "/zones", Some(duplicate_zone_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let second_zone = json!({
        "name": second_zone_name,
        "primary_ns": format!("ns1.{second_zone_name}"),
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = app.request(Method::POST, "/zones", Some(second_zone)).await;
    assert_eq!(status, StatusCode::CREATED);

    let normalize_update = json!({
        "name": format!(" {}. ", zone_name.to_ascii_uppercase()),
        "primary_ns": format!("NS1.{}.", zone_name.to_ascii_uppercase()),
        "admin_email": "Host.Master@Example.Com.",
        "ttl": 7200
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
    assert_eq!(body["zone"]["primary_ns"], format!("ns1.{zone_name}"));
    assert_eq!(body["zone"]["admin_email"], "Host.Master@example.com");

    for invalid_update in [
        json!({
            "name": format!("{}.", second_zone_name.to_ascii_uppercase()),
            "primary_ns": format!("ns1.{zone_name}"),
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": format!("{}..example.com", app.namespace()),
            "primary_ns": format!("ns1.{zone_name}"),
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": zone_name,
            "primary_ns": format!("ns1.{zone_name}"),
            "admin_email": "hostmaster@example.com",
            "ttl": 0
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

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_reject_invalid_name_and_ttl() {
    let app = TestApp::start().await;

    for invalid_zone in [
        json!({
            "name": "*.example.com",
            "primary_ns": "ns1.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": ".",
            "primary_ns": "ns.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "_tcp.example.com",
            "primary_ns": "ns._tcp.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "test..example.com",
            "primary_ns": "ns.test.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "-test.example.com",
            "primary_ns": "ns.-test.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "low-ttl.example.com",
            "primary_ns": "ns.low-ttl.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 0
        }),
        json!({
            "name": "high-ttl.example.com",
            "primary_ns": "ns.high-ttl.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 604801
        }),
    ] {
        let (status, _) = app
            .request(Method::POST, "/zones", Some(invalid_zone))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    for valid_zone in [
        json!({
            "name": app.zone_name("bailiwick.example.com"),
            "primary_ns": "ns.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": app.zone_name("bad-ns.example.com"),
            "primary_ns": "badtest.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
    ] {
        let (status, _) = app.request(Method::POST, "/zones", Some(valid_zone)).await;
        assert_eq!(status, StatusCode::CREATED);
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_dry_run_then_apply() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let content = "www IN A 192.0.2.10\nmail IN A 192.0.2.11\nftp IN CNAME www\n";

    // Dry run: reports the plan without applying it.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "dryRun": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["summary"]["added"], 3);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0);

    // Nothing applied yet.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    let before = body["items"].as_array().unwrap().len();

    // Real apply.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 3);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), before + 3);

    // Re-applying in append mode is idempotent: everything is unchanged.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["unchanged"], 3);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_replace_mode() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Seed two A records.
    app.request(
        Method::POST,
        &format!("/zones/{zone_name}/records/bulk"),
        Some(json!({
            "records": [
                { "name": "keep", "record_type": "A", "value": "192.0.2.1" },
                { "name": "drop", "record_type": "A", "value": "192.0.2.2" }
            ]
        })),
    )
    .await;

    // Replace: keep stays (same value), drop is removed, add is created.
    let content = "keep IN A 192.0.2.1\nadd IN A 192.0.2.3\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "mode": "replace" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 1);
    assert_eq!(body["summary"]["deleted"], 1);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=drop"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=add"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_reconciles_ttl() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // Seed a record with an explicit TTL of 300.
    app.request(
        Method::POST,
        &format!("/zones/{zone_name}/records/bulk"),
        Some(json!({
            "records": [
                { "name": "www", "record_type": "A", "value": "192.0.2.1", "ttl": 300 }
            ]
        })),
    )
    .await;

    let ttl_of = |body: &serde_json::Value| -> i64 {
        body["items"].as_array().unwrap()[0]["ttl"]
            .as_i64()
            .unwrap()
    };

    // Upsert with only the TTL changed: reconciled in place, not left unchanged.
    let content = "www 600 IN A 192.0.2.1\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["summary"]["added"], 0);
    assert_eq!(body["summary"]["deleted"], 0);
    assert_eq!(body["summary"]["updated"], 1);
    assert_eq!(body["summary"]["unchanged"], 0);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
    assert_eq!(ttl_of(&body), 600);

    // Re-importing the same TTL is idempotent: nothing to reconcile.
    let (_, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content, "mode": "upsert" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    // Append never modifies already-present records, TTL included.
    let (_, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": "www 900 IN A 192.0.2.1\n", "mode": "append" })),
        )
        .await;
    assert_eq!(body["summary"]["updated"], 0);
    assert_eq!(body["summary"]["unchanged"], 1);

    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=www"),
            None,
        )
        .await;
    assert_eq!(ttl_of(&body), 600);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_import_zone_file_reports_validation_errors() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    // A CNAME cannot coexist with another record of the same name.
    let content = "dup IN A 192.0.2.1\ndup IN CNAME www\n";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/zones/{zone_name}/imports"),
            Some(json!({ "content": content })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["applied"], false);
    assert!(!body["errors"].as_array().unwrap().is_empty());

    // Nothing applied because of the validation error.
    let (_, body) = app
        .request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&name=dup"),
            None,
        )
        .await;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}
