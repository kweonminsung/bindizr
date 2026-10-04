use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{RECORD_ACTIONS, TestApp, TestAppOptions};

/// Verify role and grant management over HTTP, and the guards on both.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn role_grant_lifecycle_over_http() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    let (role_name, _) = app.create_scoped_api_token().await;
    let grants = format!("/roles/{role_name}/grants");

    let (status, body) = app
        .send_request(
            Method::POST,
            &grants,
            Some(json!({
                "zone_name": zone_name,
                "actions": ["record:create", "record:read"],
                "record_name_pattern": "*.dyn",
                "record_types": "a,AAAA",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let grant_id = body["role_grant"]["id"].as_i64().unwrap();
    assert_eq!(body["role_grant"]["role_name"], json!(role_name));
    assert_eq!(body["role_grant"]["zone_name"], json!(zone_name));
    // Stored in one spelling: actions in their fixed order, types uppercase.
    assert_eq!(
        body["role_grant"]["actions"],
        json!(["record:read", "record:create"])
    );
    assert_eq!(body["role_grant"]["record_types"], "A,AAAA");

    // Without a zone the grant covers all zones.
    let (status, body) = app
        .send_request(
            Method::POST,
            &grants,
            Some(json!({ "actions": ["zone:read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["role_grant"]["zone_name"], json!(null));
    assert_eq!(body["role_grant"]["record_name_pattern"], "*");

    let (status, body) = app.send_request(Method::GET, &grants, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 2, "{body}");

    for invalid in [
        json!({ "zone_name": zone_name, "actions": [] }),
        json!({ "zone_name": zone_name, "actions": ["zone:own"] }),
        json!({ "zone_name": zone_name, "actions": ["record:read"], "record_name_pattern": "a*b" }),
        json!({ "zone_name": zone_name, "actions": ["record:read"], "record_types": "A,BOGUS" }),
        // Constraints narrow record actions, and this grant has none.
        json!({ "zone_name": zone_name, "actions": ["zone:read"], "record_types": "A" }),
        // Creating a zone acts on no zone, so it cannot be granted in one.
        json!({ "zone_name": zone_name, "actions": ["zone:create"] }),
    ] {
        let (status, _) = app
            .send_request(Method::POST, &grants, Some(invalid.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
    }

    let (status, _) = app
        .send_request(
            Method::POST,
            "/roles/no-such-role/grants",
            Some(json!({ "actions": ["zone:read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The built-in role keeps its one grant covering everything.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/roles/admin/grants",
            Some(json!({ "actions": ["zone:read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, _) = app.send_request(Method::DELETE, "/roles/admin", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A grant id is only reachable under the role that holds it.
    let other = app.zone_name("other-role");
    let (status, _) = app
        .send_request(Method::POST, "/roles", Some(json!({ "name": other })))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .send_request(
            Method::DELETE,
            &format!("/roles/{other}/grants/{grant_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = app
        .send_request(Method::DELETE, &format!("{grants}/{grant_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Deleting the zone takes the grants covering it.
    let (status, _) = app
        .send_request(
            Method::POST,
            &grants,
            Some(json!({ "zone_name": zone_name, "actions": ["zone:read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/zones/{zone_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = app.send_request(Method::GET, &grants, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");

    // A role is refused while a token holds it, and freed once none does.
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/roles/{role_name}"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/tokens/{role_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/roles/{role_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = app.send_request(Method::GET, &grants, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Verify that a role's tokens and keys are listed by role, counted on the
/// role, and named when they keep it from being deleted.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_roles_credentials_are_listed_counted_and_named() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let (role_name, _) = app.create_scoped_api_token().await;
    let key_name = format!("{role_name}-key");
    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": key_name, "role_name": role_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/roles/{role_name}/grants"),
            Some(json!({ "actions": ["zone:read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The admin token sits in another role, so only the filtered listing
    // leaves it out.
    let (status, body) = app.send_request(Method::GET, "/tokens", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["pagination"]["total"].as_u64().unwrap() >= 2, "{body}");
    let (status, body) = app
        .send_request(Method::GET, &format!("/tokens?role_name={role_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pagination"]["total"], 1, "{body}");
    assert_eq!(body["items"][0]["name"], json!(role_name));
    let (status, body) = app
        .send_request(
            Method::GET,
            &format!("/tsig-keys?role_name={role_name}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pagination"]["total"], 1, "{body}");
    assert_eq!(body["items"][0]["name"], json!(key_name));
    let (status, body) = app
        .send_request(Method::GET, "/tsig-keys?role_name=admin", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pagination"]["total"], 0, "{body}");
    let (status, body) = app
        .send_request(Method::GET, "/tokens?role_name=no-such-role", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = app
        .send_request(Method::GET, &format!("/roles/{role_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["role"]["grant_count"], 1, "{body}");
    assert_eq!(body["role"]["token_count"], 1, "{body}");
    assert_eq!(body["role"]["tsig_key_count"], 1, "{body}");
    let (status, body) = app.send_request(Method::GET, "/roles", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["name"] == json!(role_name))
        .unwrap_or_else(|| panic!("{body}"));
    assert_eq!(listed["grant_count"], 1, "{body}");
    assert_eq!(listed["token_count"], 1, "{body}");
    assert_eq!(listed["tsig_key_count"], 1, "{body}");

    let (status, body) = app
        .send_request(Method::DELETE, &format!("/roles/{role_name}"), None)
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let error = body["error"].as_str().unwrap();
    assert!(
        error.contains(&format!("API token {role_name}"))
            && error.contains(&format!("TSIG key {key_name}")),
        "{error}"
    );
}

/// Verify that tokens self grants lists the grants of the bearer's role.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_self_grants_lists_the_bearers_role_grants() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token.clone());

    let granted_zone = app.zone_name("granted.com");
    app.create_named_zone(&granted_zone).await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/roles/{scoped_name}/grants"),
            Some(json!({
                "zone_name": granted_zone,
                "actions": ["record:read"],
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
    assert_eq!(grants[0]["role_name"], json!(scoped_name));
    assert_eq!(grants[0]["zone_name"], json!(granted_zone));
    assert_eq!(grants[0]["record_name_pattern"], "*.dyn");
    assert_eq!(grants[0]["record_types"], "A,AAAA");

    // The by-name path needs `access:manage` even for the token's own role.
    let (status, _) = app
        .send_request(Method::GET, &format!("/roles/{scoped_name}/grants"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The built-in role holds one grant covering all zones.
    app.set_auth_token(admin_token);
    let (status, body) = app
        .send_request(Method::GET, "/tokens/self/grants", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"][0]["role_name"], "admin", "{body}");
    assert_eq!(body["items"][0]["zone_name"], json!(null), "{body}");
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
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

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
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let granted_zone = app.zone_name("granted.com");
    let hidden_zone = app.zone_name("hidden.com");
    app.create_named_zone(&granted_zone).await;
    app.create_named_zone(&hidden_zone).await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &granted_zone,
        "--actions",
        RECORD_ACTIONS,
    ])
    .await;
    app.set_auth_token(scoped_token);

    // An echoed spelling would name a hidden zone as stored, an absent one as typed.
    let absent_zone = app.zone_name("absent.com");
    for zone in [&hidden_zone, &absent_zone] {
        let spelled = format!("{}.", zone.to_uppercase());
        let expected = json!(format!("zone with name '{zone}' not found"));

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
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

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
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &zone_name,
        "--actions",
        RECORD_ACTIONS,
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
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let zone_name = app.zone_name("example.com");
    // Without its apex NS, so the apex holds only the TXT below.
    let (status, body) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(json!({
                "name": zone_name,
                "mname": format!("ns1.{zone_name}"),
                "rname": "admin@example.com",
                "apex_ns": false,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
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
    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &zone_name,
        "--actions",
        RECORD_ACTIONS,
        "--pattern",
        "@",
    ])
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

    assert_eq!(listed(&app).await, (1, 1));

    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &zone_name,
        "--actions",
        RECORD_ACTIONS,
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
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

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
    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &granted_zone,
        "--actions",
        RECORD_ACTIONS,
    ])
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

    // Zone actions need grants of their own; record actions carry none.
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
            &format!("/roles/{scoped_name}/grants"),
            Some(json!({ "actions": ["access:manage"] })),
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

/// Verify that role grants enforce name patterns and types.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn role_grants_enforce_name_patterns_and_types() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &zone_name,
        "--actions",
        RECORD_ACTIONS,
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
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token.clone());

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &zone_name,
        "--actions",
        RECORD_ACTIONS,
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

    app.set_auth_token(admin_token);
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
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

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

/// Verify that zone authorization rejects an ungranted batch even when
/// unparseable names leave the per-record check with no write targets.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn ungranted_bulk_of_unparseable_names_is_refused_not_validated() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

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

/// Verify that a `record:read` grant reads the zone but cannot change it.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_record_read_grant_reads_the_zone_but_cannot_change_it() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

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
    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &zone_name,
        "--actions",
        "record:read",
    ])
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

/// Verify that `/permissions` reports a role's all-zones actions and, per
/// zone, what its zone-scoped grants add, with the whole-zone record actions.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn permissions_report_what_each_zone_allows() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    // The built-in role holds everything in all zones, so no zone is listed.
    let (status, body) = app.send_request(Method::GET, "/permissions", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["all_zones"]["actions"].as_array().unwrap().len(),
        14,
        "{body}"
    );
    assert_eq!(
        body["all_zones"]["whole_zone"],
        json!([
            "record:read",
            "record:create",
            "record:update",
            "record:delete"
        ])
    );
    assert_eq!(body["zones"], json!([]));

    let narrowed = app.zone_name("narrowed.com");
    let whole = app.zone_name("whole.com");
    let untouched = app.zone_name("untouched.com");
    for zone in [&narrowed, &whole, &untouched] {
        app.create_named_zone(zone).await;
    }
    let (role, scoped_token) = app.create_scoped_api_token().await;
    for args in [
        vec!["role", "grant", &role, "--actions", "zone:read"],
        vec![
            "role",
            "grant",
            &role,
            "--zone",
            &narrowed,
            "--actions",
            "record:read,record:create",
            "--pattern",
            "*.dyn",
        ],
        vec![
            "role",
            "grant",
            &role,
            "--zone",
            &whole,
            "--actions",
            "record:read",
        ],
    ] {
        app.run_cli_success(&args).await;
    }
    app.set_auth_token(scoped_token);

    let (status, body) = app.send_request(Method::GET, "/permissions", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["all_zones"],
        json!({ "actions": ["zone:read"], "whole_zone": [] })
    );
    // Zones answering as `all_zones` are left out.
    let mut zones = body["zones"].as_array().unwrap().clone();
    zones.sort_by_key(|zone| zone["zone_name"].as_str().unwrap().to_string());
    assert_eq!(
        zones,
        vec![
            json!({
                "zone_name": narrowed,
                "actions": ["zone:read", "record:read", "record:create"],
                "whole_zone": [],
            }),
            json!({
                "zone_name": whole,
                "actions": ["zone:read", "record:read"],
                "whole_zone": ["record:read"],
            }),
        ],
        "{body}"
    );
}

/// Verify that the listing SQL and the per-record check agree on what each
/// grant reaches, on whichever backend the suite runs against.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn listings_and_lookups_agree_on_what_each_grant_reaches() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token.clone());

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    // `evil\.sub` is one label holding a dot, not a name under `sub`
    // (RFC 1035, Section 5.1).
    for (name, record_type, value) in [
        ("@", "TXT", "apex"),
        ("www", "A", "192.0.2.1"),
        ("sub", "A", "192.0.2.2"),
        ("a.sub", "A", "192.0.2.3"),
        ("a.sub", "TXT", "a"),
        ("b.a.sub", "AAAA", "2001:db8::1"),
        ("xsub", "A", "192.0.2.4"),
        ("evil\\.sub", "A", "192.0.2.5"),
        ("*.wild", "A", "192.0.2.6"),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(record_body(&zone_name, name, record_type, value)),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{name} {record_type}: {body}");
    }
    let ids = |body: &serde_json::Value| -> Vec<i64> {
        let mut ids: Vec<i64> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|record| record["id"].as_i64())
            .collect();
        ids.sort_unstable();
        ids
    };
    let listing = format!("/records?zone_name={zone_name}&limit=1000");
    let (_, body) = app.send_request(Method::GET, &listing, None).await;
    let every_id = ids(&body);

    for (index, (pattern, types)) in [
        ("*", "*"),
        ("@", "*"),
        ("sub", "*"),
        ("*.sub", "*"),
        ("*.sub", "A,AAAA"),
        ("a.sub", "TXT"),
        ("*.wild", "*"),
    ]
    .into_iter()
    .enumerate()
    {
        let role = app.zone_name(&format!("parity{index}"));
        app.set_auth_token(admin_token.clone());
        app.run_cli_success(&["role", "create", &role]).await;
        app.run_cli_success(&[
            "role",
            "grant",
            &role,
            "--zone",
            &zone_name,
            "--actions",
            "record:read",
            "--pattern",
            pattern,
            "--types",
            types,
        ])
        .await;
        let created = app
            .run_cli_success(&[
                "token", "create", &role, "--role", &role, "--output", "json",
            ])
            .await;
        let created: serde_json::Value = serde_json::from_str(&created).unwrap();
        app.set_auth_token(created["secret"].as_str().unwrap().to_string());

        let (status, body) = app.send_request(Method::GET, &listing, None).await;
        assert_eq!(status, StatusCode::OK, "{pattern} {types}: {body}");
        let listed = ids(&body);
        assert_eq!(
            body["pagination"]["total"],
            listed.len(),
            "{pattern} {types}: the count drifts from the page"
        );
        let mut looked_up = Vec::new();
        for id in &every_id {
            let (status, _) = app
                .send_request(Method::GET, &format!("/records/{id}"), None)
                .await;
            if status == StatusCode::OK {
                looked_up.push(*id);
            }
        }
        assert_eq!(
            listed, looked_up,
            "{pattern} {types}: listing and lookup disagree"
        );
        assert!(
            pattern == "@" || !listed.is_empty(),
            "{pattern} {types}: the fixture reaches nothing"
        );
    }
}

/// Verify that a grant without `record:read` still finds, by id, the records
/// its write actions cover, and nothing else.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_write_only_grant_changes_the_records_it_covers() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "other", "TXT", "not yours")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let outside_id = body["record"]["id"].as_i64().unwrap();
    // Neighbours at the challenge name the grant cannot read: their values must
    // stay out of every response the write-only role gets.
    for (record_type, value) in [("TXT", "neighbour-secret"), ("A", "192.0.2.77")] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(record_body(
                    &zone_name,
                    "_acme-challenge",
                    record_type,
                    value,
                )),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // An ACME-style client: it writes its challenge records and reads nothing.
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "role",
        "grant",
        &scoped_name,
        "--zone",
        &zone_name,
        "--actions",
        "record:create,record:update,record:delete",
        "--pattern",
        "_acme-challenge",
        "--types",
        "TXT",
    ])
    .await;
    app.set_auth_token(scoped_token);

    let (status, body) = app
        .send_request(
            Method::POST,
            "/records",
            Some(record_body(&zone_name, "_acme-challenge", "TXT", "token-1")),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let record_id = body["record"]["id"].as_i64().unwrap();
    let leaks = |body: &serde_json::Value| {
        let text = body.to_string();
        text.contains("neighbour-secret") || text.contains("192.0.2.77")
    };
    assert!(!leaks(&body), "create revealed a neighbour: {body}");
    let mut dry_run = record_body(&zone_name, "_acme-challenge", "TXT", "probe");
    dry_run["dry_run"] = json!(true);
    let (status, body) = app
        .send_request(Method::POST, "/records", Some(dry_run))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!leaks(&body), "a dry run revealed a neighbour: {body}");

    // Reading stays refused; changing what the grant covers does not.
    let (status, _) = app
        .send_request(Method::GET, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A partial update would inherit fields the grant cannot read.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({ "value": "token-2" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("missing: name, type, ttl")),
        "{body}"
    );
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/records/{record_id}"),
            Some(json!({
                "name": "_acme-challenge", "type": "TXT", "value": "token-2", "ttl": 3600,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!leaks(&body), "update revealed a neighbour: {body}");
    let (status, body) = app
        .send_request(Method::DELETE, &format!("/records/{record_id}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!leaks(&body), "delete revealed a neighbour: {body}");

    // A record outside the grant stays hidden, so its id cannot be probed.
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/records/{outside_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Create role `name` and a token in it, returning the token's secret.
async fn create_role_with_token(app: &TestApp, name: &str) -> String {
    app.run_cli_success(&["role", "create", name]).await;
    let created: serde_json::Value = serde_json::from_str(
        &app.run_cli_success(&["token", "create", name, "--role", name, "--output", "json"])
            .await,
    )
    .unwrap();
    created["secret"].as_str().unwrap().to_string()
}

/// Verify that no response or refusal a restricted role gets, on any record,
/// zone, version, import or ExternalDNS route, carries a record it cannot read.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn no_response_reveals_a_record_the_role_cannot_read() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        external_dns_enabled: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    let first_serial = app.read_zone_serial(&zone_name).await;

    // Little room left under the zone, so a longer zone name no longer fits.
    let zone_wire = zone_name
        .split('.')
        .map(|label| label.len() + 1)
        .sum::<usize>()
        + 1;
    let mut long_name = String::from("leak-marker-long");
    let mut room = 250 - zone_wire - (long_name.len() + 1);
    while room >= 2 {
        let label = (room - 1).min(63);
        long_name.push('.');
        long_name.push_str(&"a".repeat(label));
        room -= label + 1;
    }

    // Every unreadable record carries a marker in its name or value; the
    // readable `www` proves the sweep reads something. The NS goes first so
    // its DS has a delegation.
    let mut secret_ids = Vec::new();
    let mut delegation_ns_id = None;
    for (name, record_type, value) in [
        ("_acme-challenge", "TXT", "leak-marker-challenge"),
        ("_acme-challenge", "A", "192.0.2.201"),
        ("leak-marker-vault", "TXT", "kept"),
        ("leak-marker-delegation", "NS", "ns1.example.net."),
        (
            "leak-marker-delegation",
            "DS",
            "12345 13 2 abababababababababababababababababababababababababababababababab",
        ),
        (long_name.as_str(), "TXT", "kept"),
        ("www", "A", "192.0.2.10"),
    ] {
        let (status, body) = app
            .send_request(
                Method::POST,
                "/records",
                Some(record_body(&zone_name, name, record_type, value)),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = body["record"]["id"].as_i64().unwrap();
        if record_type == "NS" {
            delegation_ns_id = Some(id);
        }
        if name != "www" {
            secret_ids.push(id);
        }
    }
    let delegation_ns_id = delegation_ns_id.unwrap();
    let serial = app.read_zone_serial(&zone_name).await;

    // The shapes a write outruns its read in: a challenge writer reading only
    // `www`, a whole-zone creator, a whole-zone writer, and a zone renamer.
    let (challenge_role, challenge_token) = app.create_scoped_api_token().await;
    for (actions, pattern, types) in [
        (
            "record:create,record:update,record:delete",
            "_acme-challenge",
            "TXT",
        ),
        ("record:read", "www", "A"),
    ] {
        app.run_cli_success(&[
            "role",
            "grant",
            &challenge_role,
            "--zone",
            &zone_name,
            "--actions",
            actions,
            "--pattern",
            pattern,
            "--types",
            types,
        ])
        .await;
    }
    let creator_role = format!("{}-creator", app.namespace());
    let creator_token = create_role_with_token(&app, &creator_role).await;
    let writer_role = format!("{}-writer", app.namespace());
    let writer_token = create_role_with_token(&app, &writer_role).await;
    for (role, actions) in [
        (&creator_role, "zone:read,record:create"),
        (
            &writer_role,
            "zone:update,record:create,record:update,record:delete",
        ),
    ] {
        app.run_cli_success(&[
            "role",
            "grant",
            role,
            "--zone",
            &zone_name,
            "--actions",
            actions,
        ])
        .await;
    }
    let renamer_role = format!("{}-renamer", app.namespace());
    let renamer_token = create_role_with_token(&app, &renamer_role).await;
    app.run_cli_success(&[
        "role",
        "grant",
        &renamer_role,
        "--actions",
        "zone:update,zone:create",
    ])
    .await;

    let zone = &zone_name;
    let rename = json!({ "name": format!("renamed.{zone}"), "dry_run": true });
    let rollback = format!("/zones/{zone}/versions/{first_serial}/rollback?dry_run=true");
    let mut requests: Vec<(Method, String, Option<serde_json::Value>)> = vec![
        (Method::GET, "/zones".into(), None),
        (Method::GET, format!("/zones/{zone}"), None),
        (Method::GET, format!("/zones/{zone}/export"), None),
        (Method::GET, format!("/zones/{zone}/versions"), None),
        (
            Method::GET,
            format!("/zones/{zone}/versions/{serial}"),
            None,
        ),
        (
            Method::GET,
            format!("/zones/{zone}/versions/diff?from={first_serial}"),
            None,
        ),
        (Method::GET, format!("/zones/{zone}/dnssec"), None),
        (Method::GET, "/records".into(), None),
        (Method::GET, format!("/records?zone_name={zone}"), None),
        (Method::GET, "/records?search=leak".into(), None),
        (
            Method::GET,
            format!("/records?zone_name={zone}&name=_acme-challenge"),
            None,
        ),
        (Method::GET, "/permissions".into(), None),
        (Method::GET, "/tokens/self/grants".into(), None),
        (Method::GET, "/external-dns/domains".into(), None),
        (Method::GET, "/external-dns/records".into(), None),
        (
            Method::POST,
            "/records".into(),
            Some(json!({
                "zone_name": zone, "name": "_acme-challenge", "type": "TXT",
                "value": "probe", "dry_run": true,
            })),
        ),
        (
            Method::POST,
            "/records".into(),
            Some(record_body(zone, "_acme-challenge", "TXT", "token-1")),
        ),
        (
            Method::POST,
            "/records/bulk".into(),
            Some(json!({
                "zone_name": zone,
                "records": [{ "name": "_acme-challenge", "type": "TXT", "value": "token-2" }],
                "dry_run": true,
            })),
        ),
        (
            Method::DELETE,
            format!("/records?zone_name={zone}&name=_acme-challenge&type=TXT&dry_run=true"),
            None,
        ),
        (
            Method::POST,
            format!("/zones/{zone}/import"),
            Some(json!({
                // Joining an existing set puts that set on both sides of the diff.
                "content": format!(
                    "$ORIGIN {zone}.\n$TTL 3600\n_acme-challenge IN TXT \"fresh\"\n"
                ),
                "mode": "append",
                "dry_run": true,
            })),
        ),
        (
            Method::POST,
            "/external-dns/changes".into(),
            Some(json!({
                "creates": [{
                    "name": format!("_acme-challenge.{zone}"), "type": "TXT",
                    "values": ["\"token-3\""],
                }],
            })),
        ),
        (Method::PUT, format!("/zones/{zone}"), Some(rename.clone())),
        (Method::POST, rollback.clone(), None),
    ];
    for id in &secret_ids {
        requests.push((Method::GET, format!("/records/{id}"), None));
        // A partial update would echo the fields it inherits.
        for body in [
            json!({ "dry_run": true }),
            json!({ "ttl": 60 }),
            json!({ "value": "overwrite" }),
            json!({
                "name": "_acme-challenge", "type": "TXT", "value": "overwrite", "ttl": 3600,
                "dry_run": true,
            }),
        ] {
            requests.push((Method::PUT, format!("/records/{id}"), Some(body)));
        }
        // Previewed, so every role meets every record.
        requests.push((Method::DELETE, format!("/records/{id}?dry_run=true"), None));
    }

    let leaks = |body: &serde_json::Value| {
        let text = body.to_string();
        text.contains("leak-marker") || text.contains("192.0.2.201")
    };
    for (role, token) in [
        (&challenge_role, &challenge_token),
        (&creator_role, &creator_token),
        (&writer_role, &writer_token),
        (&renamer_role, &renamer_token),
    ] {
        app.set_auth_token(token.clone());
        let mut succeeded = 0;
        for (method, path, body) in &requests {
            let (status, response) = app.send_request(method.clone(), path, body.clone()).await;
            assert!(
                !leaks(&response),
                "{role}: {method} {path} answered {status} with an unreadable record: {response}"
            );
            succeeded += usize::from(status.is_success());
        }
        // Equal silence from refusals would prove nothing.
        assert!(
            succeeded >= 8,
            "{role}: only {succeeded} requests succeeded"
        );
    }

    // Refusals the previews cannot reach: the DS check a delete by id trips.
    app.set_auth_token(writer_token);
    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/records/{delegation_ns_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(!leaks(&body), "a delete by id named its record: {body}");
    // A rollback reads the version it restores.
    let (status, body) = app.send_request(Method::POST, &rollback, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("'record:read'")),
        "{body}"
    );
    // A rename refused over a record the renamer cannot read leaves it unnamed.
    app.set_auth_token(renamer_token);
    let (status, body) = app
        .send_request(Method::PUT, &format!("/zones/{zone}"), Some(rename))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(!leaks(&body), "a rename named a record: {body}");
}

/// Verify that an import creating its zone from a server needs the mode's
/// all-zones record rights before any transfer starts, so `zone:create`
/// alone cannot make the daemon fetch from an arbitrary host.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn a_zone_creating_import_needs_its_record_rights_before_fetching() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token.clone());

    let (role_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&["role", "grant", &role_name, "--actions", "zone:create"])
        .await;
    app.set_auth_token(scoped_token.clone());

    // Nothing listens there: a refusal before the fetch is 403, an attempted
    // fetch fails as invalid input.
    let zone_name = app.zone_name("fetched.example.com");
    let import = json!({ "create": true, "from_server": "127.0.0.1:1", "mode": "upsert" });
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(import.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("'record:create' over all zones whole")),
        "{body}"
    );

    // The grants are read per request, so the same token sees the new one.
    app.set_auth_token(admin_token);
    app.run_cli_success(&[
        "role",
        "grant",
        &role_name,
        "--actions",
        "record:create,record:delete",
    ])
    .await;
    app.set_auth_token(scoped_token);
    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/zones/{zone_name}/import"),
            Some(import),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.starts_with("AXFR from 127.0.0.1:1 failed")),
        "{body}"
    );
}

/// Verify that renaming a zone needs `zone:create`, so a zone-scoped
/// `zone:update` cannot probe other zones' names through rename conflicts.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn renaming_a_zone_needs_zone_create() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token.clone());

    let zone_name = app.zone_name("example.com");
    app.create_named_zone(&zone_name).await;
    let other_zone = app.zone_name("other.com");
    app.create_named_zone(&other_zone).await;

    let (role_name, scoped_token) = app.create_scoped_api_token().await;
    app.run_cli_success(&[
        "role",
        "grant",
        &role_name,
        "--zone",
        &zone_name,
        "--actions",
        "zone:update",
    ])
    .await;
    app.set_auth_token(scoped_token.clone());

    // Refused before any name is looked up, taken or not.
    for name in [other_zone.as_str(), "unused.example.net"] {
        let (status, body) = app
            .send_request(
                Method::PUT,
                &format!("/zones/{zone_name}"),
                Some(json!({ "name": name, "dry_run": true })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|message| message.contains("'zone:create' in all zones")),
            "{body}"
        );
    }
    // The settings stay the role's to change.
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "description": "kept", "dry_run": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    app.set_auth_token(admin_token);
    app.run_cli_success(&["role", "grant", &role_name, "--actions", "zone:create"])
        .await;
    app.set_auth_token(scoped_token);
    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}"),
            Some(json!({ "name": "unused.example.net", "dry_run": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
