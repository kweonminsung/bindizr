//! The logs over HTTP: what a management change leaves in the audit log, what
//! a request leaves in the access log, whom each names, and who may read them.

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::common::{TestApp, TestAppOptions};

/// List the rows `query` selects, newest first, with the total the page reports.
async fn list_audit_log(app: &TestApp, query: &str) -> (Vec<Value>, u64) {
    let (status, body) = app
        .send_request(Method::GET, &format!("/logs/audit?{query}"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().unwrap().clone();
    (items, body["pagination"]["total"].as_u64().unwrap())
}

/// Verify that every management change leaves one row naming the object,
/// the operation and the token, and that a refused request leaves none.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn audit_log_records_management_changes_with_their_actor() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (admin_name, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);
    let actor = json!({ "kind": "token", "name": admin_name });

    let role_name = format!("{}-audited", app.namespace());
    let token_name = format!("{role_name}-token");
    let tsig_key_name = format!("{role_name}-key");
    let secondary_name = format!("{role_name}-ns2");
    let policy_name = format!("{role_name}-policy");
    let zone_name = app.zone_name("audited.example");

    let (status, body) = app
        .send_request(Method::POST, "/roles", Some(json!({ "name": role_name })))
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

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": token_name, "role_name": role_name })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tsig-keys",
            Some(json!({ "name": tsig_key_name, "role_name": role_name })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/secondaries",
            Some(json!({ "name": secondary_name, "address": "192.0.2.77" })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/secondaries/{secondary_name}"),
            Some(json!({ "enabled": false })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/secondaries/{secondary_name}"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/dnssec-policies",
            Some(json!({ "name": policy_name })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/dnssec-policies/{policy_name}"),
            Some(json!({ "signature_validity_days": 21 })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app
        .send_request(
            Method::DELETE,
            &format!("/dnssec-policies/{policy_name}"),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    app.create_named_zone(&zone_name).await;

    let (status, deleted_zone) = app
        .send_request(Method::DELETE, &format!("/zones/{zone_name}"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{deleted_zone}");

    // A refused request leaves nothing: the role exists, so its create conflicts.
    let (status, _) = app
        .send_request(Method::POST, "/roles", Some(json!({ "name": role_name })))
        .await;

    assert_eq!(status, StatusCode::CONFLICT);

    // The role and its grant share the role's name; newest first.
    let (logs, total) = list_audit_log(&app, &format!("entity_name={role_name}")).await;

    assert_eq!(total, 2, "{logs:?}");
    assert_eq!(logs[0]["entity"], "role_grant");
    assert_eq!(logs[0]["operation"], "create");
    assert_eq!(
        logs[0]["detail"],
        "zone_name all zones, actions zone:read, record_name_pattern *, record_types *"
    );
    assert_eq!(logs[1]["entity"], "role");
    assert_eq!(logs[1]["operation"], "create");
    assert!(logs[1]["detail"].is_null(), "{logs:?}");

    for log in &logs {
        assert_eq!(log["entity_name"], role_name);
        assert_eq!(log["change_source"], "api");
        assert_eq!(log["changed_by"], actor, "{log}");
        assert!(log["created_at"].is_string(), "{log}");
    }

    let expected_operations = [
        ("token", token_name.as_str(), vec!["create"]),
        ("tsig_key", tsig_key_name.as_str(), vec!["create"]),
        (
            "secondary",
            secondary_name.as_str(),
            vec!["delete", "update", "create"],
        ),
        (
            "dnssec_policy",
            policy_name.as_str(),
            vec!["delete", "update", "create"],
        ),
        // A zone's creation is its first version; only its deletion is logged.
        ("zone", zone_name.as_str(), vec!["delete"]),
    ];

    for (entity, name, operations) in expected_operations {
        let (logs, total) =
            list_audit_log(&app, &format!("entity={entity}&entity_name={name}")).await;

        assert_eq!(total, operations.len() as u64, "{entity} {name}: {logs:?}");
        let listed: Vec<&str> = logs
            .iter()
            .map(|log| log["operation"].as_str().unwrap())
            .collect();

        assert_eq!(listed, operations, "{entity} {name}");
        assert!(logs.iter().all(|log| log["changed_by"] == actor));
    }

    // The detail: what a change set, or what an update moved.
    let (logs, _) = list_audit_log(&app, &format!("entity=token&entity_name={token_name}")).await;

    assert_eq!(
        logs[0]["detail"],
        format!("role_name {role_name}, expires_at never")
    );

    let (logs, _) = list_audit_log(
        &app,
        &format!("entity=secondary&entity_name={secondary_name}"),
    )
    .await;

    assert!(logs[0]["detail"].is_null(), "{logs:?}");
    assert_eq!(logs[1]["detail"], "enabled true -> false");
    assert_eq!(
        logs[2]["detail"],
        "address 192.0.2.77:53, notify_key_name none"
    );

    let (logs, _) = list_audit_log(
        &app,
        &format!("entity=dnssec_policy&entity_name={policy_name}"),
    )
    .await;

    assert_eq!(logs[1]["detail"], "signature_validity_days 14 -> 21");

    let (logs, _) = list_audit_log(&app, &format!("entity=zone&entity_name={zone_name}")).await;

    assert_eq!(
        logs[0]["detail"],
        format!(
            "records_deleted {}, versions_deleted {}",
            deleted_zone["records_deleted"], deleted_zone["versions_deleted"]
        )
    );

    // Any column, either direction; newest first by default.
    let (logs, _) = list_audit_log(
        &app,
        &format!("entity=secondary&entity_name={secondary_name}&sort=operation&order=asc"),
    )
    .await;
    let listed: Vec<&str> = logs
        .iter()
        .map(|log| log["operation"].as_str().unwrap())
        .collect();

    assert_eq!(listed, ["create", "delete", "update"]);

    let (logs, _) = list_audit_log(&app, &format!("entity_name={role_name}&order=asc")).await;

    assert_eq!(logs[0]["entity"], "role");
    assert_eq!(logs[1]["entity"], "role_grant");

    let (status, body) = app
        .send_request(Method::GET, "/logs/audit?sort=detail", None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    // The entity filter is the closed set; a time window is half-open and ordered.
    let (status, body) = app
        .send_request(Method::GET, "/logs/audit?entity=record", None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (_, total) = list_audit_log(&app, "since=2100-01-01T00:00:00Z").await;

    assert_eq!(total, 0);

    let (status, body) = app
        .send_request(
            Method::GET,
            "/logs/audit?since=2100-01-01T00:00:00Z&until=2000-01-01T00:00:00Z",
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (logs, _) = list_audit_log(&app, &format!("entity_name={role_name}&limit=1")).await;

    assert_eq!(logs.len(), 1);
}

/// Verify that reading the log needs `log:read`, which only an all-zones grant carries.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn audit_log_requires_log_read_in_all_zones() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (admin_name, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token.clone());
    let zone_name = app.zone_name("audit-scope.example");

    app.create_named_zone(&zone_name).await;

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token.clone());

    let (status, body) = app.send_request(Method::GET, "/logs/audit", None).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "FORBIDDEN");

    // The action concerns nothing a zone owns, so a zone grant cannot carry it.
    app.set_auth_token(admin_token);

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/roles/{scoped_name}/grants"),
            Some(json!({ "zone_name": zone_name, "actions": ["log:read"] })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/roles/{scoped_name}/grants"),
            Some(json!({ "actions": ["log:read"] })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The reader sees the grant that admitted it, made by the admin token.
    app.set_auth_token(scoped_token);

    let (logs, total) = list_audit_log(
        &app,
        &format!("entity=role_grant&entity_name={scoped_name}"),
    )
    .await;

    assert_eq!(total, 1, "{logs:?}");
    assert_eq!(logs[0]["operation"], "create");
    assert_eq!(
        logs[0]["changed_by"],
        json!({ "kind": "token", "name": admin_name })
    );
}

/// Verify that a management request leaves an access row naming its token and outcome, that
/// a refusal by the auth layer leaves one naming no caller, and that probes and queries do not.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn access_log_records_requests_with_their_caller_and_outcome() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (admin_name, admin_token) = app.create_api_token().await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    let zone_name = app.zone_name("access-log.example");
    let zone_path = format!("/zones/{zone_name}");

    // Answered: the token that verified is the caller; the query is not kept.
    app.set_auth_token(admin_token.clone());
    app.create_named_zone(&zone_name).await;

    let (status, body) = app
        .send_request(Method::GET, &format!("{zone_path}?secret=not-kept"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let log = app
        .wait_for_access_log(&format!("caller_name={admin_name}&result=ok"), |log| {
            log["method"] == "GET" && log["target"] == zone_path
        })
        .await;

    assert_eq!(log["source"], "api", "{log}");
    assert_eq!(log["status"], "200", "{log}");
    assert_eq!(log["address"], "127.0.0.1", "{log}");
    assert_eq!(
        log["caller"],
        json!({ "kind": "token", "name": admin_name })
    );
    assert!(log["error"].is_null(), "{log}");

    // Denied by the role: 403, under the token that verified.
    app.set_auth_token(scoped_token);

    let (status, body) = app.send_request(Method::DELETE, &zone_path, None).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a zone the scope cannot see stays hidden: {body}"
    );

    let (status, body) = app.send_request(Method::GET, "/logs/access", None).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    app.set_auth_token(admin_token.clone());

    let hidden = app
        .wait_for_access_log(&format!("caller_name={scoped_name}"), |log| {
            log["method"] == "DELETE" && log["target"] == zone_path
        })
        .await;

    // A zone the role cannot see is a failure like any 404, so the log
    // cannot tell a scope that the zone exists.
    assert_eq!(hidden["result"], "failed", "{hidden}");
    assert_eq!(hidden["status"], "404", "{hidden}");

    let forbidden = app
        .wait_for_access_log(&format!("caller_name={scoped_name}&result=denied"), |log| {
            log["target"] == "/logs/access"
        })
        .await;

    assert_eq!(forbidden["status"], "403", "{forbidden}");
    assert!(
        forbidden["error"].as_str().unwrap().contains("log:read"),
        "{forbidden}"
    );

    // Refused by the auth layer: 401, and no token verified to name.
    app.set_auth_token("not-a-token".to_string());

    let (status, body) = app.send_request(Method::GET, &zone_path, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = app.send_request(Method::GET, "/health", None).await;

    assert_eq!(status, StatusCode::OK, "{body}");

    app.set_auth_token(admin_token);

    let refused = app
        .wait_for_access_log("result=denied&source=api", |log| {
            log["target"] == zone_path && log["status"] == "401"
        })
        .await;

    assert!(refused["caller"].is_null(), "{refused}");
    assert_eq!(refused["error"], "invalid or expired token", "{refused}");

    // Answered by the router's fallbacks, which no route's layer covers: an
    // unknown path and a method its path does not take are saved too.
    let (status, body) = app.send_request(Method::GET, "/no-such-route", None).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = app.send_request(Method::PATCH, "/zones", None).await;

    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{body}");

    // An extension method may be any length; it is cut to the column's width
    // so the insert cannot fail on MySQL or PostgreSQL.
    let long_method = Method::from_bytes(b"LONGCUSTOMREQUEST").unwrap();
    let (status, body) = app.send_request(long_method, "/zones", None).await;

    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{body}");

    for (method, target, status) in [
        ("GET", "/no-such-route", "404"),
        ("PATCH", "/zones", "405"),
        ("LONGCUSTOMREQUES", "/zones", "405"),
    ] {
        let log = app
            .wait_for_access_log("result=failed&source=api", |log| {
                log["method"] == method && log["target"] == target
            })
            .await;

        assert_eq!(log["status"], status, "{log}");
    }

    let (status, body) = app
        .send_request(Method::GET, "/logs/access?limit=1000", None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|log| log["target"] != "/health"
                && !log["target"].as_str().unwrap().contains('?')),
        "{body}"
    );

    for query in [
        "source=socket",
        "result=refused",
        "address=localhost",
        "since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z",
        "sort=method",
    ] {
        let (status, body) = app
            .send_request(Method::GET, &format!("/logs/access?{query}"), None)
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
        assert_eq!(body["code"], "INVALID_INPUT", "{query}: {body}");
    }
}
