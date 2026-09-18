use reqwest::{Method, StatusCode, header};
use serde_json::{Value, json};

use crate::common::{ExternalDnsAdapter, TestApp, TestAppOptions};

const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

/// Create a zone fixture through the API.
async fn create_zone(app: &TestApp, zone_name: &str) {
    let (status, _) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "default_ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
}

/// Grant the test token access to a zone.
async fn grant_zone(app: &TestApp, zone_name: &str, token_name: &str) {
    app.run_cli_success(&["token", "grant", token_name, zone_name])
        .await;
}

/// Collect values matching an owner and type from an API response.
fn record_values(body: &Value, name: &str, record_type: &str) -> Vec<String> {
    body["records"]
        .as_array()
        .expect("records array")
        .iter()
        .filter(|r| r["name"] == name && r["record_type"] == record_type)
        .flat_map(|r| r["values"].as_array().expect("record values").iter())
        .map(|v| v.as_str().expect("record value").to_string())
        .collect()
}

/// Verify that external DNS routes are not registered when disabled.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_routes_are_not_registered_when_disabled() {
    let app = TestApp::start_local().await;

    let (status, _) = app
        .send_request(Method::GET, "/external-dns/domains", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = app
        .send_request(Method::POST, "/external-dns/changes", Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify that external DNS domain listing reflects token grants.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_domain_listing_reflects_token_grants() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let granted_zone = app.zone_name("granted.com");
    let other_zone = app.zone_name("other.com");
    create_zone(&app, &granted_zone).await;
    create_zone(&app, &other_zone).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    grant_zone(&app, &granted_zone, &scoped_name).await;

    // A global token sees every zone.
    let (status, body) = app
        .send_request(Method::GET, "/external-dns/domains", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let domains = body["domains"].as_array().expect("domains array");
    assert!(domains.contains(&json!(granted_zone)));
    assert!(domains.contains(&json!(other_zone)));

    // A scoped token sees only its grants (this feeds the DomainFilter).
    app.set_auth_token(scoped_token);
    let (status, body) = app
        .send_request(Method::GET, "/external-dns/domains", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["domains"], json!([granted_zone]));
}

/// Verify that a grant narrowed to a subtree narrows the domain filter.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_grant_narrowed_to_a_subtree_narrows_the_domain_filter() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("narrowed.com");
    create_zone(&app, &zone_name).await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "token",
        "grant",
        &scoped_name,
        &zone_name,
        "--pattern",
        "*.k8s",
    ])
    .await;

    // The filter carries the granted subtree, not the zone: ExternalDNS plans
    // inside what the apply accepts instead of failing the whole sync on the
    // first record outside the grant.
    app.set_auth_token(scoped_token);
    let (status, body) = app
        .send_request(Method::GET, "/external-dns/domains", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["domains"],
        json!([format!("k8s.{zone_name}")]),
        "{body}"
    );

    // A read-only grant leaves ExternalDNS nothing to write, so it stays out.
    app.run_cli_success(&[
        "token",
        "grant",
        &scoped_name,
        &zone_name,
        "--pattern",
        "*.readonly",
        "--read-only",
    ])
    .await;
    let (status, body) = app
        .send_request(Method::GET, "/external-dns/domains", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["domains"],
        json!([format!("k8s.{zone_name}")]),
        "{body}"
    );
}

/// Verify that external DNS changes apply and stay idempotent.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_changes_apply_and_stay_idempotent() {
    let app = TestApp::start_with_options(TestAppOptions {
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;
    let base_serial = app.read_zone_serial(&zone_name).await;

    let create = json!({
        "creates": [
            {"name": format!("app.{zone_name}"), "record_type": "A", "ttl": 300,
             "values": ["192.0.2.2", "192.0.2.1"]},
            {"name": format!("app.{zone_name}"), "record_type": "TXT",
             "values": ["\"heritage=external-dns,external-dns/owner=default\""]}
        ]
    });

    let (status, body) = app
        .send_request(Method::POST, "/external-dns/changes", Some(create.clone()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed_zones"], json!([zone_name]));
    assert_eq!(body["records_added"], json!(3));
    assert_eq!(app.read_zone_serial(&zone_name).await, base_serial + 1);

    // Same create again: no-op, no serial bump.
    let (status, body) = app
        .send_request(Method::POST, "/external-dns/changes", Some(create))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed_zones"], json!([]));
    assert_eq!(app.read_zone_serial(&zone_name).await, base_serial + 1);

    let (status, body) = app
        .send_request(Method::GET, "/external-dns/records", None)
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
        .send_request(
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
    assert_eq!(app.read_zone_serial(&zone_name).await, base_serial + 2);

    // Delete, then delete again as a no-op.
    let delete = json!({
        "deletes": [{"name": app_fqdn, "record_type": "A",
                     "values": ["192.0.2.1", "192.0.2.3"]}]
    });
    let (status, body) = app
        .send_request(Method::POST, "/external-dns/changes", Some(delete.clone()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records_deleted"], json!(2));
    assert_eq!(app.read_zone_serial(&zone_name).await, base_serial + 3);

    let (status, body) = app
        .send_request(Method::POST, "/external-dns/changes", Some(delete))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changed_zones"], json!([]));
    assert_eq!(app.read_zone_serial(&zone_name).await, base_serial + 3);
}

/// Verify that external DNS changes reject ungranted zones atomically.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_changes_reject_ungranted_zones_atomically() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token.clone());

    let granted_zone = app.zone_name("granted.com");
    let ungranted_zone = app.zone_name("blocked.com");
    create_zone(&app, &granted_zone).await;
    create_zone(&app, &ungranted_zone).await;
    let base_serial = app.read_zone_serial(&granted_zone).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    grant_zone(&app, &granted_zone, &scoped_name).await;

    app.set_auth_token(scoped_token);
    let (status, body) = app
        .send_request(
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
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");
    // Worded as for a name no zone covers, so the hidden zone stays hidden.
    assert_eq!(
        body["error"],
        json!(format!("No zone is authoritative for 'b.{ungranted_zone}'"))
    );

    // Nothing was applied for the granted zone either.
    app.set_auth_token(global_token);
    assert_eq!(app.read_zone_serial(&granted_zone).await, base_serial);
    let (_, body) = app
        .send_request(Method::GET, "/external-dns/records", None)
        .await;
    assert!(record_values(&body, &format!("a.{granted_zone}"), "A").is_empty());
}

/// Verify that external DNS never falls back from ungranted subzone to granted parent.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_never_falls_back_from_ungranted_subzone_to_granted_parent() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
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
        .send_request(
            Method::POST,
            "/external-dns/changes",
            Some(json!({
                "creates": [{"name": format!("api.{child_zone}"), "record_type": "A",
                             "values": ["192.0.2.1"]}]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(child_zone.as_str())
    );

    // A name with no authoritative zone is rejected, not auto-created.
    let (status, body) = app
        .send_request(
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

/// Verify that external DNS changes enforce record validation.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_changes_enforce_record_validation() {
    let app = TestApp::start_with_options(TestAppOptions {
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;

    let (status, _) = app
        .send_request(
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
        .send_request(
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
        .send_request(
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

/// Verify that adapter serves webhook protocol with scoped token.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn adapter_serves_webhook_protocol_with_scoped_token() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    create_zone(&app, &zone_name).await;

    // The adapter runs with a scoped token granted exactly this zone.
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    grant_zone(&app, &zone_name, &scoped_name).await;

    // Without a token, the provider API itself rejects the request.
    let unauthenticated = reqwest::Client::new()
        .get(format!("{}/external-dns/domains", app.base_url()))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status().as_u16(), 401);

    let adapter = ExternalDnsAdapter::spawn(app.base_url(), &scoped_token).await;
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

    // AdjustEndpoints canonicalizes on the server: type case, address
    // spelling, and equivalent duplicates resolve to the stored form.
    let response = client
        .post(format!("{}/adjustendpoints", adapter.base_url))
        .header(header::CONTENT_TYPE, MEDIA_TYPE)
        .body(
            json!([{"dnsName": format!("v6.{zone_name}"), "recordType": "aaaa",
                    "targets": ["2001:0DB8::1", "2001:db8:0:0:0:0:0:1"], "recordTTL": 300}])
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let adjusted: Value = response.json().await.unwrap();
    assert_eq!(
        adjusted,
        json!([{"dnsName": format!("v6.{zone_name}"), "recordType": "AAAA",
                "targets": ["2001:db8::1"], "recordTTL": 300}])
    );

    // A wrong token answers 503, not the upstream 401: external-dns retries
    // only 5xx, and granting or replacing the token is meant to heal the sync
    // rather than leave the change set dropped as permanently bad.
    let bad_adapter = ExternalDnsAdapter::spawn(app.base_url(), "not-a-real-token").await;
    let response = client
        .get(format!("{}/records", bad_adapter.base_url))
        .header(header::ACCEPT, MEDIA_TYPE)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);

    // The same token failure turns the adapter unready, instead of leaving it
    // green on bindizr's unauthenticated health endpoint.
    let health = client
        .get(format!("{}/healthz", bad_adapter.health_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status().as_u16(), 503);
}

/// Verify that external DNS record listing spans read pages.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn external_dns_record_listing_spans_read_pages() {
    let app = TestApp::start_with_options(TestAppOptions {
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let zone_name = app.zone_name("paged.com");
    create_zone(&app, &zone_name).await;

    // Past the read page, so the listing has to tile without dropping a row.
    const RECORDS: usize = 5_100;
    let zone_file: String = (0..RECORDS)
        .map(|i| {
            format!(
                "r{i} 3600 IN A 10.{}.{}.{}\n",
                i / 65536,
                (i / 256) % 256,
                i % 256
            )
        })
        .collect();
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(json!({ "content": zone_file, "mode": "upsert" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true, "{body}");

    let (status, body) = app
        .send_request(Method::GET, "/external-dns/records", None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let listed = body["records"].as_array().expect("records array");
    let a_records = listed
        .iter()
        .filter(|record| record["record_type"] == "A")
        .count();
    assert_eq!(a_records, RECORDS, "{}", listed.len());

    let names: std::collections::HashSet<&str> = listed
        .iter()
        .filter_map(|record| record["name"].as_str())
        .collect();
    assert_eq!(names.len(), listed.len(), "a row was listed twice");
}
