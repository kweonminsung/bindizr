use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::TestApp;

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_read_update_delete_round_trip() {
    let app = TestApp::start().await;

    let create_zone_request = json!({
        "name": "test.com",
        "primary_ns": "ns1.test.com",
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

    let zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(zone_name, "test.com");

    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], "test.com");

    let (status, body) = app.request(Method::GET, "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    let update_zone_request = json!({
        "name": "updated-test.com",
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
            &format!("/zones/{zone_name}"),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let updated_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(updated_zone_name, "updated-test.com");

    let (status, _) = app
        .request(Method::DELETE, &format!("/zones/{updated_zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .request(Method::GET, &format!("/zones/{updated_zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_list_filters_support_ranges_search_and_pagination() {
    let app = TestApp::start().await;
    app.create_test_zone().await;

    let create_zone_request = json!({
        "name": "filtered.net",
        "primary_ns": "ns1.filtered.net",
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
            "/zones?search=filtered&min_ttl=7000&max_ttl=8000",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], "filtered.net");

    let (status, body) = app
        .request(Method::GET, "/zones?limit=1&offset=1", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], "filtered.net");
    assert_eq!(body["pagination"]["total"], 2);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 1);

    let (status, _) = app.request(Method::GET, "/zones?limit=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_and_update_apply_validation_and_normalization() {
    let app = TestApp::start().await;

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
        "name": " Test.Example.Com. ",
        "primary_ns": "NS1.Test.Example.Com.",
        "admin_email": "Host.Master@Example.Com.",
        "ttl": 3600
    });
    let (status, body) = app
        .request(Method::POST, "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], "test.example.com");
    assert_eq!(body["zone"]["primary_ns"], "ns1.test.example.com");
    assert_eq!(body["zone"]["admin_email"], "Host.Master@example.com");

    let duplicate_zone_request = json!({
        "name": "test.example.com.",
        "primary_ns": "ns2.test.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = app
        .request(Method::POST, "/zones", Some(duplicate_zone_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let second_zone = json!({
        "name": "second.example.com",
        "primary_ns": "ns1.second.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = app.request(Method::POST, "/zones", Some(second_zone)).await;
    assert_eq!(status, StatusCode::CREATED);

    let normalize_update = json!({
        "name": " Test.Example.Com. ",
        "primary_ns": "NS1.Test.Example.Com.",
        "admin_email": "Host.Master@Example.Com.",
        "ttl": 7200
    });
    let (status, body) = app
        .request(
            Method::PUT,
            "/zones/test.example.com",
            Some(normalize_update),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], "test.example.com");
    assert_eq!(body["zone"]["primary_ns"], "ns1.test.example.com");
    assert_eq!(body["zone"]["admin_email"], "Host.Master@example.com");

    for invalid_update in [
        json!({
            "name": "Second.Example.Com.",
            "primary_ns": "ns1.test.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "test..example.com",
            "primary_ns": "ns1.test.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "test.example.com",
            "primary_ns": "ns1.test.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 0
        }),
    ] {
        let (status, _) = app
            .request(Method::PUT, "/zones/test.example.com", Some(invalid_update))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn zone_create_rejects_invalid_names_and_ttl_bounds() {
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
            "name": "bailiwick.example.com",
            "primary_ns": "ns.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
        json!({
            "name": "test.example.com",
            "primary_ns": "badtest.example.com",
            "admin_email": "hostmaster@example.com",
            "ttl": 3600
        }),
    ] {
        let (status, _) = app.request(Method::POST, "/zones", Some(valid_zone)).await;
        assert_eq!(status, StatusCode::CREATED);
    }
}
