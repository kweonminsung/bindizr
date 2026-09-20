use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

/// Verify that global token grant management over HTTP.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn global_token_grant_management_over_http() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (global_name, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    let (scoped_name, _) = app.create_scoped_api_token().await;

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/tokens/{scoped_name}/grants"),
            Some(json!({ "zone_name": zone_name, "record_types": "A,AAAA" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let grant_id = body["token_grant"]["id"].as_i64().unwrap();
    assert_eq!(body["token_grant"]["record_types"], "A,AAAA");
    assert_eq!(body["token_grant"]["api_token"], json!(scoped_name));
    assert_eq!(body["token_grant"]["zone_name"], json!(zone_name));

    // The grant is visible from both ends: the token's list and the zone's.
    let (status, body) = app
        .send_request(Method::GET, &format!("/tokens/{scoped_name}/grants"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/token-grants"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["api_token"], json!(scoped_name));

    // A global token already covers every zone, so it cannot be granted one.
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/tokens/{global_name}/grants"),
            Some(json!({ "zone_name": zone_name })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A grant id is only reachable under the token that holds it.
    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/tokens/{global_name}/grants/{grant_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/tokens/{scoped_name}/grants/{grant_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .send_request(Method::GET, &format!("/tokens/{scoped_name}/grants"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].as_array().unwrap().is_empty());
}

/// Verify that tokens self grants lists the bearers own grants.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_self_grants_lists_the_bearers_own_grants() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token.clone());

    let granted_zone = app.zone_name("granted.com");
    app.create_named_zone(&granted_zone).await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/tokens/{scoped_name}/grants"),
            Some(json!({
                "zone_name": granted_zone,
                "record_name_pattern": "*.dyn",
                "record_types": "A,AAAA",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    app.set_auth_token(scoped_token);
    let (status, body) = app
        .send_request(Method::GET, "/tokens/self/grants", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let grants = body["items"].as_array().unwrap();
    assert_eq!(grants.len(), 1, "{body}");
    assert_eq!(grants[0]["api_token"], json!(scoped_name));
    assert_eq!(grants[0]["zone_name"], json!(granted_zone));
    assert_eq!(grants[0]["record_name_pattern"], "*.dyn");
    assert_eq!(grants[0]["record_types"], "A,AAAA");

    // The by-name path stays global-only even for the token's own name.
    let (status, _) = app
        .send_request(Method::GET, &format!("/tokens/{scoped_name}/grants"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A global token holds no grants.
    app.set_auth_token(global_token);
    let (status, body) = app
        .send_request(Method::GET, "/tokens/self/grants", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["items"].as_array().unwrap().is_empty(), "{body}");
}

/// Build a record creation request for authorization tests.
fn record_body(zone_name: &str, name: &str, record_type: &str, value: &str) -> serde_json::Value {
    json!({
        "name": name,
        "type": record_type,
        "value": value,
        "zone_name": zone_name,
    })
}

/// Verify that scoped token without grants sees nothing.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_without_grants_sees_nothing() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (_, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, body) = app.send_request(Method::GET, "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["pagination"]["total"], json!(0));

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "app", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify that hidden and absent zones read alike whatever the spelling.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn hidden_and_absent_zones_read_alike_whatever_the_spelling() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let granted_zone = app.zone_name("granted.com");
    let hidden_zone = app.zone_name("hidden.com");
    app.create_named_zone(&granted_zone).await;
    app.create_named_zone(&hidden_zone).await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&["token", "grant", &scoped_name, &granted_zone])
        .await;
    app.set_auth_token(scoped_token);

    // An echoed spelling would name a hidden zone as stored, an absent one as typed.
    let absent_zone = app.zone_name("absent.com");
    for zone in [&hidden_zone, &absent_zone] {
        let spelled = format!("{}.", zone.to_uppercase());
        let expected = json!(format!("Zone with name '{zone}' not found"));

        let (status, body) = app
            .send_request(Method::GET, &format!("/zones/{spelled}"), None)
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"], expected, "{body}");

        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(record_body(&spelled, "www", "A", "192.0.2.1")),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"], expected, "{body}");
    }
}

/// Verify that a narrowed grant reads only what it may write.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_narrowed_grant_reads_only_what_it_may_write() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "host.dyn", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let granted_id = body["record"]["id"].as_i64().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "www", "A", "192.0.2.2")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let outside_id = body["record"]["id"].as_i64().unwrap();

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "token",
        "grant",
        &scoped_name,
        &zone_name,
        "--pattern",
        "*.dyn",
    ])
    .await;
    app.set_auth_token(scoped_token);

    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&limit=1000"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let listed_ids: Vec<i64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_i64().unwrap())
        .collect();
    assert!(listed_ids.contains(&granted_id));
    assert!(!listed_ids.contains(&outside_id));
    // The count is narrowed in SQL beside the page, so a scoped listing does
    // not advertise rows it will never hand over.
    assert_eq!(body["pagination"]["total"], 1, "{body}");

    let (status, _) = app
        .send_request(Method::GET, &format!("/records/{granted_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .send_request(Method::GET, &format!("/records/{outside_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A view the zone is rebuilt from cannot be handed over half-written.
    let (status, _) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .send_request(
            Method::GET,
            &format!("/zones/{zone_name}/versions/diff?from=1&to=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Verify that a grants pattern and types narrow the count too.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_grants_pattern_and_types_narrow_the_count_too() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    for (name, record_type, value) in [
        ("@", "TXT", "apex"),
        ("host.dyn", "A", "192.0.2.1"),
        ("host.dyn", "TXT", "text"),
        ("www", "A", "192.0.2.2"),
        // One label that happens to contain a dot: matching by text reads it
        // as under `dyn`, matching by label does not.
        (r"a\.dyn", "A", "192.0.2.3"),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(record_body(&zone_name, name, record_type, value)),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // Granting runs over the daemon socket, which carries no token.
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&["token", "grant", &scoped_name, &zone_name, "--pattern", "@"])
        .await;
    app.set_auth_token(scoped_token);

    let listed = async |app: &TestApp| -> (usize, u64) {
        let (status, body) = app
            .send_request(
                Method::GET,
                &format!("/records?zone_name={zone_name}&limit=1000"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (
            body["items"].as_array().unwrap().len(),
            body["pagination"]["total"].as_u64().unwrap(),
        )
    };

    // The apex holds only the TXT above: a new zone carries no records.
    assert_eq!(listed(&app).await, (1, 1));

    app.run_cli_success(&[
        "token",
        "grant",
        &scoped_name,
        &zone_name,
        "--pattern",
        "*.dyn",
        "--types",
        "A",
    ])
    .await;
    // The apex grant still stands, so its one row comes with the one A record
    // under `dyn`; the dotted label is stored as `a\046dyn`, so SQL leaves it
    // out of the count too.
    assert_eq!(listed(&app).await, (2, 2));

    // And out of the pages: its slot holds the next visible row, not a gap.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?zone_name={zone_name}&sort=name&order=asc&limit=1&offset=1"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["items"][0]["name"],
        format!("host.dyn.{zone_name}."),
        "{body}"
    );
    assert_eq!(body["pagination"]["total"], 2, "{body}");
}

/// Verify that scoped token sees and writes only granted zones.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_sees_and_writes_only_granted_zones() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let granted_zone = app.zone_name("granted.com");
    let other_zone = app.zone_name("other.com");
    app.create_named_zone(&granted_zone).await;
    app.create_named_zone(&other_zone).await;

    // Persist a record in the ungranted zone so listing assertions can prove
    // exclusion, not pass over an empty zone.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&other_zone, "app", "A", "192.0.2.9")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let ungranted_record_id = body["record"]["id"].as_i64().unwrap();

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&["token", "grant", &scoped_name, &granted_zone])
        .await;

    app.set_auth_token(scoped_token);

    // Zone listing is filtered to grants; ungranted zones read as 404.
    let (status, body) = app.send_request(Method::GET, "/zones", None).await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|z| z["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&granted_zone.as_str()));
    assert!(!names.contains(&other_zone.as_str()));
    assert_eq!(body["pagination"]["total"], json!(1));

    let (status, _) = app
        .send_request(Method::GET, &format!("/zones/{other_zone}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Record writes work in the granted zone and 404 elsewhere.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&granted_zone, "app", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&other_zone, "app", "A", "192.0.2.2")),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "ZONE_NOT_FOUND");

    // Record listing only surfaces granted zones.
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/records?search={}&limit=1000", app.namespace()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let listed_ids: Vec<i64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_i64().unwrap())
        .collect();
    assert!(listed_ids.contains(&record_id));
    assert!(!listed_ids.contains(&ungranted_record_id));

    // The zone plane requires a global token.
    let new_zone = app.zone_name("new.com");
    let (status, _) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": new_zone,
                "mname": format!("ns1.{new_zone}"),
                "rname": "admin@example.com",
                "default_ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/zones/{granted_zone}"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // So does a serial-bumping NOTIFY.
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/zones/{granted_zone}/notify?bump_serial=true"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // So does grant management (no self-escalation).
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/tokens/{scoped_name}/grants"),
            Some(json!({ "zone_name": granted_zone })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Records of ungranted zones are invisible even when addressed by id.
    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/records/{ungranted_record_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Deleting an own record still works.
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Verify that `token` grants enforce name patterns and types.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn token_grants_enforce_name_patterns_and_types() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "token",
        "grant",
        &scoped_name,
        &zone_name,
        "--pattern",
        "*.dyn",
        "--types",
        "A,TXT",
    ])
    .await;

    app.set_auth_token(scoped_token);

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "host.dyn", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Outside the name pattern.
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "www", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Outside the type list.
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(
                &zone_name,
                "host.dyn",
                "CNAME",
                "cdn.example.net",
            )),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Verify that a delete filter outside the grant is refused whether or not
/// it matches a record, and that such a record reads as absent by id.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_delete_filter_outside_the_grant_is_refused_whether_or_not_it_matches() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token.clone());

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "token",
        "grant",
        &scoped_name,
        &zone_name,
        "--pattern",
        "*.dyn",
        "--types",
        "A,TXT",
    ])
    .await;

    // The answer must not depend on whether the record exists.
    let filter = format!("/records?zone_name={zone_name}&name=www&type=A");
    let paths = [filter.clone(), format!("{filter}&dry_run=true")];
    app.set_auth_token(scoped_token.clone());
    for path in &paths {
        let (status, body) = app.send_request(Method::DELETE, path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
    }

    app.set_auth_token(global_token);
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "www", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let record_id = body["record"]["id"].as_i64().unwrap();

    app.set_auth_token(scoped_token);
    for path in &paths {
        let (status, body) = app.send_request(Method::DELETE, path, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
    }

    // Addressed by id, the record reads as absent, as it does on GET.
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "ttl": 600 })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify that ungranted bulk is refused before it can probe the zone.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ungranted_bulk_is_refused_before_it_can_probe_the_zone() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "app", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (_, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    // Bulk must authorize before validating, or the constraint error answers
    // first and tells an ungranted caller what the zone already holds.
    for dry_run in [false, true] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records/bulk",
                Some(json!({
                    "zone_name": zone_name,
                    "records": [
                        { "name": "app", "type": "A", "value": "192.0.2.1" }
                    ],
                    "dry_run": dry_run,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "dry_run={dry_run}: {body}");
        assert!(
            !body.to_string().contains("already exists"),
            "dry_run={dry_run} leaked the existing record: {body}"
        );
    }
}

/// Verify that zone authorization rejects an ungranted batch even when none of its names can be
/// parsed.
///
/// Such a batch produces no write targets for the per-record authorization check.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ungranted_bulk_of_unparseable_names_is_refused_not_validated() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (_, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records/bulk",
            Some(json!({
                "zone_name": zone_name,
                "records": [
                    { "name": "bad name", "type": "A", "value": "192.0.2.1" }
                ]
            })),
        )
        .await;

    // 400 here would confirm the zone exists and that its validation ran.
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "ZONE_NOT_FOUND", "{body}");
}

/// Verify that a read only grant reads the zone but cannot change it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_read_only_grant_reads_the_zone_but_cannot_change_it() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "app", "A", "192.0.2.1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = body["record"]["id"].as_i64().unwrap();

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&["token", "grant", &scoped_name, &zone_name, "--read-only"])
        .await;
    app.set_auth_token(scoped_token);

    let (status, _) = app
        .send_request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .send_request(Method::GET, &format!("/zones/{zone_name}/export"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "other", "A", "192.0.2.2")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
