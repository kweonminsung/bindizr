use axum::http::StatusCode;

use crate::common::TestContext;

#[tokio::test]
async fn zone_create_read_update_delete_round_trip() {
    let ctx = TestContext::new().await;

    // Test POST /zones (create)
    let create_zone_request = serde_json::json!({
        "name": "test.com",
        "primary_ns": "ns1.test.com",
        "admin_email": "admin@test.com",
        "ttl": 3600,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });

    let (status, body) = ctx
        .make_request("POST", "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(zone_name, "test.com");

    // Test GET /zones/{name}
    let (status, body) = ctx
        .make_request("GET", &format!("/zones/{}", zone_name), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zone"]["name"], "test.com");

    // Test GET /zones (with data)
    let (status, body) = ctx.make_request("GET", "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    // Test PUT /zones/{name} (update)
    let update_zone_request = serde_json::json!({
        "name": "updated-test.com",
        "primary_ns": "ns2.external-dns.net",
        "admin_email": "admin@updated-test.com",
        "ttl": 7200,
        "refresh": 14400,
        "retry": 7200,
        "expire": 1209600,
        "minimum_ttl": 172800
    });

    let (status, body) = ctx
        .make_request(
            "PUT",
            &format!("/zones/{}", zone_name),
            Some(update_zone_request),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let updated_zone_name = body["zone"]["name"].as_str().unwrap();
    assert_eq!(updated_zone_name, "updated-test.com");

    // Test DELETE /zones/{name}
    let (status, _) = ctx
        .make_request("DELETE", &format!("/zones/{}", updated_zone_name), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Verify deletion
    let (status, _) = ctx
        .make_request("GET", &format!("/zones/{}", updated_zone_name), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn zone_list_filters_support_ranges_search_and_pagination() {
    let ctx = TestContext::new().await;
    ctx.create_test_zone().await;

    let create_zone_request = serde_json::json!({
        "name": "filtered.net",
        "primary_ns": "ns1.filtered.net",
        "admin_email": "admin@filtered.net",
        "ttl": 7200,
        "refresh": 7200,
        "retry": 3600,
        "expire": 604800,
        "minimum_ttl": 86400
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = ctx
        .make_request(
            "GET",
            "/zones?search=filtered&min_ttl=7000&max_ttl=8000",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], "filtered.net");

    let (status, body) = ctx
        .make_request("GET", "/zones?limit=1&offset=1", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["items"].as_array().unwrap();
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0]["name"], "filtered.net");
    assert_eq!(body["pagination"]["total"], 2);
    assert_eq!(body["pagination"]["limit"], 1);
    assert_eq!(body["pagination"]["offset"], 1);

    let (status, _) = ctx.make_request("GET", "/zones?limit=-1", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn zone_create_rejects_invalid_admin_email_forms() {
    let ctx = TestContext::new().await;

    let invalid_admin_email = serde_json::json!({
        "name": "invalid-admin-email.com",
        "primary_ns": "ns1.invalid-admin-email.com",
        "admin_email": "admin@@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(invalid_admin_email))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let soa_mailbox_admin_email = serde_json::json!({
        "name": "soa-mailbox.com",
        "primary_ns": "ns1.soa-mailbox.com",
        "admin_email": "hostmaster.soa-mailbox.com.",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(soa_mailbox_admin_email))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn zone_create_normalizes_names_and_rejects_duplicates() {
    let ctx = TestContext::new().await;

    let create_zone_request = serde_json::json!({
        "name": " Test.Example.Com. ",
        "primary_ns": "NS1.Test.Example.Com.",
        "admin_email": "Host.Master@Example.Com.",
        "ttl": 3600
    });
    let (status, body) = ctx
        .make_request("POST", "/zones", Some(create_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["zone"]["name"], "test.example.com");
    assert_eq!(body["zone"]["primary_ns"], "ns1.test.example.com");
    assert_eq!(body["zone"]["admin_email"], "Host.Master@example.com");

    let duplicate_zone_request = serde_json::json!({
        "name": "test.example.com.",
        "primary_ns": "ns2.test.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(duplicate_zone_request))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let child_zone_request = serde_json::json!({
        "name": "child.test.example.com",
        "primary_ns": "ns1.child.test.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(child_zone_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let apex_primary_ns_request = serde_json::json!({
        "name": "apex-ns.example.com",
        "primary_ns": "apex-ns.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 604800
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(apex_primary_ns_request))
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn zone_create_rejects_invalid_names_and_ttl_bounds() {
    let ctx = TestContext::new().await;

    let invalid_zone_name = serde_json::json!({
        "name": "*.example.com",
        "primary_ns": "ns1.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(invalid_zone_name))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let root_zone = serde_json::json!({
        "name": ".",
        "primary_ns": "ns.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx.make_request("POST", "/zones", Some(root_zone)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let underscore_zone = serde_json::json!({
        "name": "_tcp.example.com",
        "primary_ns": "ns._tcp.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(underscore_zone))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let empty_label_zone = serde_json::json!({
        "name": "test..example.com",
        "primary_ns": "ns.test.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(empty_label_zone))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let hyphen_edge_zone = serde_json::json!({
        "name": "-test.example.com",
        "primary_ns": "ns.-test.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(hyphen_edge_zone))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let out_of_bailiwick_ns = serde_json::json!({
        "name": "bailiwick.example.com",
        "primary_ns": "ns.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(out_of_bailiwick_ns))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let suffix_boundary_ns = serde_json::json!({
        "name": "test.example.com",
        "primary_ns": "badtest.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 3600
    });
    let (status, _) = ctx
        .make_request("POST", "/zones", Some(suffix_boundary_ns))
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let low_ttl = serde_json::json!({
        "name": "low-ttl.example.com",
        "primary_ns": "ns.low-ttl.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 0
    });
    let (status, _) = ctx.make_request("POST", "/zones", Some(low_ttl)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let high_ttl = serde_json::json!({
        "name": "high-ttl.example.com",
        "primary_ns": "ns.high-ttl.example.com",
        "admin_email": "hostmaster@example.com",
        "ttl": 604801
    });
    let (status, _) = ctx.make_request("POST", "/zones", Some(high_ttl)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
