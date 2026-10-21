//! The audit log over HTTP: what a management change leaves, whom it names,
//! and who may read it.

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::common::{TestApp, TestAppOptions};

/// The rows `query` selects, newest first, with the total the page reports.
async fn list_audit_log(app: &TestApp, query: &str) -> (Vec<Value>, u64) {
    let (status, body) = app
        .send_request(Method::GET, &format!("/audit?{query}"), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().expect("items").clone();
    (items, body["pagination"]["total"].as_u64().expect("total"))
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
    let key_name = format!("{role_name}-key");
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
            Some(json!({ "name": key_name, "role_name": role_name })),
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
    let (rows, total) = list_audit_log(&app, &format!("entity_name={role_name}")).await;

    assert_eq!(total, 2, "{rows:?}");
    assert_eq!(rows[0]["entity"], "role_grant");
    assert_eq!(rows[0]["operation"], "create");
    assert_eq!(
        rows[0]["detail"],
        "zone_name all zones, actions zone:read, record_name_pattern *, record_types *"
    );
    assert_eq!(rows[1]["entity"], "role");
    assert_eq!(rows[1]["operation"], "create");
    assert!(rows[1]["detail"].is_null(), "{rows:?}");

    for row in &rows {
        assert_eq!(row["entity_name"], role_name);
        assert_eq!(row["change_source"], "api");
        assert_eq!(row["changed_by"], actor, "{row}");
        assert!(row["created_at"].is_string(), "{row}");
    }

    let expected_operations = [
        ("token", token_name.as_str(), vec!["create"]),
        ("tsig_key", key_name.as_str(), vec!["create"]),
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
        let (rows, total) =
            list_audit_log(&app, &format!("entity={entity}&entity_name={name}")).await;

        assert_eq!(total, operations.len() as u64, "{entity} {name}: {rows:?}");
        let listed: Vec<&str> = rows
            .iter()
            .map(|row| row["operation"].as_str().unwrap())
            .collect();

        assert_eq!(listed, operations, "{entity} {name}");
        assert!(rows.iter().all(|row| row["changed_by"] == actor));
    }

    // The detail: what a change set, or what an update moved.
    let (rows, _) = list_audit_log(&app, &format!("entity=token&entity_name={token_name}")).await;

    assert_eq!(
        rows[0]["detail"],
        format!("role_name {role_name}, expires_at never")
    );

    let (rows, _) = list_audit_log(
        &app,
        &format!("entity=secondary&entity_name={secondary_name}"),
    )
    .await;

    assert!(rows[0]["detail"].is_null(), "{rows:?}");
    assert_eq!(rows[1]["detail"], "enabled true -> false");
    assert_eq!(
        rows[2]["detail"],
        "address 192.0.2.77:53, notify_key_name none"
    );

    let (rows, _) = list_audit_log(
        &app,
        &format!("entity=dnssec_policy&entity_name={policy_name}"),
    )
    .await;

    assert_eq!(rows[1]["detail"], "signature_validity_days 14 -> 21");

    let (rows, _) = list_audit_log(&app, &format!("entity=zone&entity_name={zone_name}")).await;

    assert_eq!(
        rows[0]["detail"],
        format!(
            "records_deleted {}, versions_deleted {}",
            deleted_zone["records_deleted"], deleted_zone["versions_deleted"]
        )
    );

    // Any column, either direction; newest first by default.
    let (rows, _) = list_audit_log(
        &app,
        &format!("entity=secondary&entity_name={secondary_name}&sort=operation&order=asc"),
    )
    .await;
    let listed: Vec<&str> = rows
        .iter()
        .map(|row| row["operation"].as_str().unwrap())
        .collect();

    assert_eq!(listed, ["create", "delete", "update"]);

    let (rows, _) = list_audit_log(&app, &format!("entity_name={role_name}&order=asc")).await;

    assert_eq!(rows[0]["entity"], "role");
    assert_eq!(rows[1]["entity"], "role_grant");

    let (status, body) = app
        .send_request(Method::GET, "/audit?sort=detail", None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    // The entity filter is the closed set; a time window is half-open and ordered.
    let (status, body) = app
        .send_request(Method::GET, "/audit?entity=record", None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (_, total) = list_audit_log(&app, "since=2100-01-01T00:00:00Z").await;

    assert_eq!(total, 0);

    let (status, body) = app
        .send_request(
            Method::GET,
            "/audit?since=2100-01-01T00:00:00Z&until=2000-01-01T00:00:00Z",
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (rows, _) = list_audit_log(&app, &format!("entity_name={role_name}&limit=1")).await;

    assert_eq!(rows.len(), 1);
}

/// Verify that reading the log needs `audit:read`, which only an all-zones grant carries.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn audit_log_needs_audit_read_in_all_zones() {
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

    let (status, body) = app.send_request(Method::GET, "/audit", None).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["code"], "FORBIDDEN");

    // The action concerns nothing a zone owns, so a zone grant cannot carry it.
    app.set_auth_token(admin_token);

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/roles/{scoped_name}/grants"),
            Some(json!({ "zone_name": zone_name, "actions": ["audit:read"] })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (status, body) = app
        .send_request(
            Method::POST,
            &format!("/roles/{scoped_name}/grants"),
            Some(json!({ "actions": ["audit:read"] })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The reader sees the grant that admitted it, made by the admin token.
    app.set_auth_token(scoped_token);

    let (rows, total) = list_audit_log(
        &app,
        &format!("entity=role_grant&entity_name={scoped_name}"),
    )
    .await;

    assert_eq!(total, 1, "{rows:?}");
    assert_eq!(rows[0]["operation"], "create");
    assert_eq!(
        rows[0]["changed_by"],
        json!({ "kind": "token", "name": admin_name })
    );
}
