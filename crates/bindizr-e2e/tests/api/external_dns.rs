use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};

use crate::common::{ExternalDnsAdapter, TestApp, TestAppOptions};

const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

fn enabled_options() -> TestAppOptions {
    TestAppOptions {
        external_dns_enabled: true,
        ..TestAppOptions::default()
    }
}

fn authed_enabled_options() -> TestAppOptions {
    TestAppOptions {
        require_authentication: true,
        external_dns_enabled: true,
        ..TestAppOptions::default()
    }
}

async fn create_zone(app: &TestApp, zone_name: &str) {
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "primary_ns": format!("ns1.{zone_name}"),
                "admin_email": "admin@example.com",
                "ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

async fn grant_zone(app: &TestApp, zone_name: &str, token_name: &str) {
    app.run_cli_success(&[
        "zone",
        "token-policy",
        "add",
        zone_name,
        "--token",
        token_name,
    ])
    .await;
}

async fn zone_serial(app: &TestApp, zone_name: &str) -> i64 {
    let (status, body) = app
        .request(Method::GET, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    body["zone"]["serial"].as_i64().expect("zone serial")
}

fn record_values(body: &Value, name: &str, record_type: &str) -> Vec<String> {
    body["records"]
        .as_array()
        .expect("records array")
        .iter()
        .filter(|r| r["name"] == name && r["record_type"] == record_type)
        .map(|r| r["value"].as_str().expect("record value").to_string())
        .collect()
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_routes_are_not_registered_when_disabled() {
    let app = TestApp::start_with_options(TestAppOptions::default()).await;

    let (status, _) = app.request(Method::GET, "/external-dns/zones", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = app
        .request(Method::POST, "/external-dns/changes", Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_zone_listing_reflects_token_grants() {
    let mut app = TestApp::start_with_options(authed_enabled_options()).await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token.clone());

    let granted_zone = app.zone_name("granted.com");
    let other_zone = app.zone_name("other.com");
    create_zone(&app, &granted_zone).await;
    create_zone(&app, &other_zone).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    grant_zone(&app, &granted_zone, &scoped_name).await;

    // A global token sees every zone.
    let (status, body) = app.request(Method::GET, "/external-dns/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    let zones = body["zones"].as_array().expect("zones array");
    assert!(zones.contains(&json!(granted_zone)));
    assert!(zones.contains(&json!(other_zone)));

    // A scoped token sees only its grants (this feeds the DomainFilter).
    app.set_auth_token(scoped_token);
    let (status, body) = app.request(Method::GET, "/external-dns/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["zones"], json!([granted_zone]));
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_changes_apply_and_stay_idempotent() {
    let app = TestApp::start_with_options(enabled_options()).await;
    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;
    let base_serial = zone_serial(&app, &zone_name).await;

    let create = json!({
        "creates": [
            {"name": format!("app.{zone_name}"), "record_type": "A", "ttl": 300,
             "values": ["192.0.2.2", "192.0.2.1"]},
            {"name": format!("app.{zone_name}"), "record_type": "TXT",
             "values": ["\"heritage=external-dns,external-dns/owner=default\""]}
        ]
    });

    let (status, body) = app
        .request(Method::POST, "/external-dns/changes", Some(create.clone()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed_zones"], json!([zone_name]));
    assert_eq!(body["records_added"], json!(3));
    assert_eq!(zone_serial(&app, &zone_name).await, base_serial + 1);

    // Same create again: no-op, no serial bump.
    let (status, body) = app
        .request(Method::POST, "/external-dns/changes", Some(create))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed_zones"], json!([]));
    assert_eq!(zone_serial(&app, &zone_name).await, base_serial + 1);

    let (status, body) = app
        .request(Method::GET, "/external-dns/records", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let app_fqdn = format!("app.{zone_name}");
    assert_eq!(
        record_values(&body, &app_fqdn, "A"),
        vec!["192.0.2.1", "192.0.2.2"]
    );
    // Ownership TXT round-trips in its quoted presentation form.
    assert_eq!(
        record_values(&body, &app_fqdn, "TXT"),
        vec!["\"heritage=external-dns,external-dns/owner=default\""]
    );

    // Update replacing one target: one more serial bump.
    let (status, body) = app
        .request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "updates": [{
                    "old": {"name": app_fqdn, "record_type": "A", "ttl": 300,
                             "values": ["192.0.2.1", "192.0.2.2"]},
                    "new": {"name": app_fqdn, "record_type": "A", "ttl": 300,
                             "values": ["192.0.2.1", "192.0.2.3"]}
                }]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records_added"], json!(1));
    assert_eq!(body["records_deleted"], json!(1));
    assert_eq!(zone_serial(&app, &zone_name).await, base_serial + 2);

    // Delete, then delete again as a no-op.
    let delete = json!({
        "deletes": [{"name": app_fqdn, "record_type": "A",
                     "values": ["192.0.2.1", "192.0.2.3"]}]
    });
    let (status, body) = app
        .request(Method::POST, "/external-dns/changes", Some(delete.clone()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records_deleted"], json!(2));
    assert_eq!(zone_serial(&app, &zone_name).await, base_serial + 3);

    let (status, body) = app
        .request(Method::POST, "/external-dns/changes", Some(delete))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed_zones"], json!([]));
    assert_eq!(zone_serial(&app, &zone_name).await, base_serial + 3);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_changes_reject_ungranted_zones_atomically() {
    let mut app = TestApp::start_with_options(authed_enabled_options()).await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token.clone());

    let granted_zone = app.zone_name("granted.com");
    let ungranted_zone = app.zone_name("blocked.com");
    create_zone(&app, &granted_zone).await;
    create_zone(&app, &ungranted_zone).await;
    let base_serial = zone_serial(&app, &granted_zone).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    grant_zone(&app, &granted_zone, &scoped_name).await;

    app.set_auth_token(scoped_token);
    let (status, body) = app
        .request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [
                    {"name": format!("a.{granted_zone}"), "record_type": "A", "values": ["192.0.2.1"]},
                    {"name": format!("b.{ungranted_zone}"), "record_type": "A", "values": ["192.0.2.2"]}
                ]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "FORBIDDEN");

    // Nothing was applied for the granted zone either.
    app.set_auth_token(global_token);
    assert_eq!(zone_serial(&app, &granted_zone).await, base_serial);
    let (_, body) = app
        .request(Method::GET, "/external-dns/records", None)
        .await;
    assert!(record_values(&body, &format!("a.{granted_zone}"), "A").is_empty());
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_never_falls_back_from_ungranted_subzone_to_granted_parent() {
    let mut app = TestApp::start_with_options(authed_enabled_options()).await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let parent_zone = app.zone_name("example.com");
    let child_zone = format!("internal.{parent_zone}");
    create_zone(&app, &parent_zone).await;
    create_zone(&app, &child_zone).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    grant_zone(&app, &parent_zone, &scoped_name).await;

    // The name resolves to the (ungranted) child zone, never the parent.
    app.set_auth_token(scoped_token);
    let (status, body) = app
        .request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [{"name": format!("api.{child_zone}"), "record_type": "A",
                             "values": ["192.0.2.1"]}]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(child_zone.as_str())
    );

    // A name with no authoritative zone is rejected, not auto-created.
    let (status, body) = app
        .request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [{"name": "app.unmanaged-zone.org", "record_type": "A",
                             "values": ["192.0.2.1"]}]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_changes_enforce_record_validation() {
    let app = TestApp::start_with_options(enabled_options()).await;
    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;

    let (status, _) = app
        .request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [{"name": format!("www.{zone_name}"), "record_type": "A",
                             "values": ["192.0.2.1"]}]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // CNAME exclusivity against the existing A record.
    let (status, body) = app
        .request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [{"name": format!("www.{zone_name}"), "record_type": "CNAME",
                             "values": ["cdn.example.net"]}]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "RECORD_CONFLICT");

    // Unsupported record types are rejected explicitly.
    let (status, _) = app
        .request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [{"name": format!("mail.{zone_name}"), "record_type": "MX",
                             "values": ["10 mail.example.com."]}]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn adapter_serves_webhook_protocol_with_scoped_token() {
    let mut app = TestApp::start_with_options(authed_enabled_options()).await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;

    // The adapter runs with a scoped token granted exactly this zone.
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    grant_zone(&app, &zone_name, &scoped_name).await;

    // Without a token, the provider API itself rejects the request.
    let unauthenticated = reqwest::Client::new()
        .get(format!("{}/external-dns/zones", app.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status().as_u16(), 401);

    let adapter = ExternalDnsAdapter::spawn(app.base_url(), Some(&scoped_token)).await;
    let client = reqwest::Client::new();

    // Negotiation: exact media type and the granted zones as DomainFilter.
    let response = client
        .get(&adapter.base_url)
        .header(header::ACCEPT, MEDIA_TYPE)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(MEDIA_TYPE)
    );
    let filter: Value = response.json().await.unwrap();
    assert_eq!(filter["include"], json!([zone_name]));

    // ApplyChanges through the adapter: one webhook call, 204 on success.
    let response = client
        .post(format!("{}/records", adapter.base_url))
        .header(header::CONTENT_TYPE, MEDIA_TYPE)
        .body(
            json!({
                "create": [{"dnsName": format!("app.{zone_name}"), "targets": ["192.0.2.1"],
                            "recordType": "A", "recordTTL": 300}]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 204);

    // Records through the adapter come back as grouped endpoints.
    let response = client
        .get(format!("{}/records", adapter.base_url))
        .header(header::ACCEPT, MEDIA_TYPE)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let endpoints: Value = response.json().await.unwrap();
    let endpoint = endpoints
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["dnsName"] == json!(format!("app.{zone_name}")) && e["recordType"] == "A")
        .expect("created endpoint is listed");
    assert_eq!(endpoint["targets"], json!(["192.0.2.1"]));
    assert_eq!(endpoint["recordTTL"], json!(300));

    // A wrong token surfaces as a permanent 401 through the adapter.
    let bad_adapter = ExternalDnsAdapter::spawn(app.base_url(), Some("not-a-real-token")).await;
    let response = client
        .get(format!("{}/records", bad_adapter.base_url))
        .header(header::ACCEPT, MEDIA_TYPE)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}
