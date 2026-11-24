//! The logs over HTTP: what a management change leaves in the activity log, what
//! a request leaves in the access log, whom each names, and who may read them.

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use crate::common::{TestApp, TestAppOptions};

/// List the rows `query` selects, newest first, with the total the page reports.
async fn list_activity_log(app: &TestApp, query: &str) -> (Vec<Value>, u64) {
    let (status, body) = app
        .send_request(Method::GET, &format!("/logs/activity?{query}"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().unwrap().clone();
    (items, body["pagination"]["total"].as_u64().unwrap())
}

/// Verify that every management change leaves one row naming the object,
/// the operation and the token, and that a refused request leaves none.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn activity_log_records_management_changes_with_their_actor() {
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
    let (logs, total) = list_activity_log(&app, &format!("name={role_name}")).await;

    assert_eq!(total, 2, "{logs:?}");
    assert_eq!(logs[0]["operation"], "role_grant.create");
    assert_eq!(
        logs[0]["detail"],
        "zone_name all zones, actions zone:read, record_name_pattern *, record_types *"
    );
    assert_eq!(logs[1]["operation"], "role.create");
    assert!(logs[1]["detail"].is_null(), "{logs:?}");

    for log in &logs {
        assert_eq!(log["target"]["name"], role_name);
        assert_eq!(log["source"], "api");
        assert_eq!(log["actor"], actor, "{log}");
        assert!(log["created_at"].is_string(), "{log}");
        assert!(log.get("occurred_at").is_none(), "{log}");
    }

    let expected_operations = [
        ("token", token_name.as_str(), vec!["token.create"]),
        ("tsig_key", tsig_key_name.as_str(), vec!["tsig_key.create"]),
        (
            "secondary",
            secondary_name.as_str(),
            vec!["secondary.delete", "secondary.update", "secondary.create"],
        ),
        (
            "dnssec_policy",
            policy_name.as_str(),
            vec![
                "dnssec_policy.delete",
                "dnssec_policy.update",
                "dnssec_policy.create",
            ],
        ),
        (
            "zone",
            zone_name.as_str(),
            vec!["zone.delete", "zone.create"],
        ),
    ];

    for (entity, name, operations) in expected_operations {
        let (logs, total) = list_activity_log(&app, &format!("entity={entity}&name={name}")).await;

        assert_eq!(total, operations.len() as u64, "{entity} {name}: {logs:?}");
        let listed: Vec<&str> = logs
            .iter()
            .map(|log| log["operation"].as_str().unwrap())
            .collect();

        assert_eq!(listed, operations, "{entity} {name}");
        assert!(logs.iter().all(|log| log["actor"] == actor));
    }

    // The detail: what a change set, or what an update moved.
    let (logs, _) = list_activity_log(&app, &format!("entity=token&name={token_name}")).await;

    assert_eq!(
        logs[0]["detail"],
        format!("role_name {role_name}, expires_at never")
    );

    let (logs, _) =
        list_activity_log(&app, &format!("entity=secondary&name={secondary_name}")).await;

    assert!(logs[0]["detail"].is_null(), "{logs:?}");
    assert_eq!(logs[1]["detail"], "enabled true -> false");
    assert_eq!(
        logs[2]["detail"],
        "address 192.0.2.77:53, notify_tsig_key_name none"
    );

    let (logs, _) =
        list_activity_log(&app, &format!("entity=dnssec_policy&name={policy_name}")).await;

    assert_eq!(logs[1]["detail"], "signature_validity_days 14 -> 21");

    let (logs, _) = list_activity_log(&app, &format!("entity=zone&name={zone_name}")).await;

    assert_eq!(
        logs[0]["detail"],
        format!(
            "records_deleted {}, versions_deleted {}",
            deleted_zone["records_deleted"], deleted_zone["versions_deleted"]
        )
    );

    // Any column, either direction; newest first by default.
    let (logs, _) = list_activity_log(
        &app,
        &format!("entity=secondary&name={secondary_name}&sort=operation&order=asc"),
    )
    .await;
    let listed: Vec<&str> = logs
        .iter()
        .map(|log| log["operation"].as_str().unwrap())
        .collect();

    assert_eq!(
        listed,
        ["secondary.create", "secondary.delete", "secondary.update"]
    );

    let (logs, _) =
        list_activity_log(&app, &format!("name={role_name}&sort=created_at&order=asc")).await;

    assert_eq!(logs[0]["operation"], "role.create");
    assert_eq!(logs[1]["operation"], "role_grant.create");

    let (status, body) = app
        .send_request(Method::GET, "/logs/activity?sort=detail", None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    // The entity filter is the closed set; a time window is half-open and ordered.
    let (status, body) = app
        .send_request(Method::GET, "/logs/activity?entity=unrecognised", None)
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (_, total) = list_activity_log(&app, "since=2100-01-01T00:00:00Z").await;

    assert_eq!(total, 0);

    let (status, body) = app
        .send_request(
            Method::GET,
            "/logs/activity?since=2100-01-01T00:00:00Z&until=2000-01-01T00:00:00Z",
            None,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "INVALID_INPUT");

    let (logs, _) = list_activity_log(&app, &format!("name={role_name}&limit=1")).await;

    assert_eq!(logs.len(), 1);
}

/// Verify that a change to a zone's DNSSEC settings, which no version holds,
/// leaves an activity row saying what moved, even when no zone data changed.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn activity_log_records_dnssec_settings_changes() {
    let app = TestApp::start().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();

    let (status, body) = app
        .send_request(
            Method::PUT,
            &format!("/zones/{zone_name}/dnssec"),
            Some(json!({ "parent_ns_addrs": ["192.0.2.53"] })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let (logs, total) = list_activity_log(
        &app,
        &format!("operation=dnssec.update&zone_name={zone_name}"),
    )
    .await;

    assert_eq!(total, 1, "{logs:?}");
    assert_eq!(logs[0]["operation"], "dnssec.update");
    assert_eq!(logs[0]["detail"], "parent_ns_addrs none -> 192.0.2.53");
}

/// Verify that reading the log needs `log:read`, which only an all-zones grant carries.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn activity_log_requires_log_read_in_all_zones() {
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

    let (status, body) = app.send_request(Method::GET, "/logs/activity", None).await;

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

    let (logs, total) =
        list_activity_log(&app, &format!("entity=role_grant&name={scoped_name}")).await;

    assert_eq!(total, 1, "{logs:?}");
    assert_eq!(logs[0]["operation"], "role_grant.create");
    assert_eq!(
        logs[0]["actor"],
        json!({ "kind": "token", "name": admin_name })
    );
}

/// Verify that a management request leaves an access row naming its actor and result, that
/// a refusal by the auth layer leaves one naming no actor, and that probes and queries do not.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn access_log_records_requests_with_their_actor_and_result() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (admin_name, admin_token) = app.create_api_token().await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    let zone_name = app.zone_name("access-log.example");
    let zone_path = format!("/zones/{zone_name}");

    // Answered: the token that verified is the actor; the query is not kept.
    app.set_auth_token(admin_token.clone());
    app.create_named_zone(&zone_name).await;

    let (status, body) = app
        .send_request(Method::GET, &format!("{zone_path}?secret=not-kept"), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");

    let log = app
        .wait_for_access_log(
            &format!("actor_name={admin_name}&result=ok&client_ip=127.0.0.1&sort=response_code"),
            |log| log["method"] == "GET" && log["target"] == zone_path,
        )
        .await;

    assert_eq!(log["source"], "api", "{log}");
    assert_eq!(log["response_code"], "200", "{log}");
    assert_eq!(log["client_ip"], "127.0.0.1", "{log}");
    assert_eq!(log["actor"], json!({ "kind": "token", "name": admin_name }));
    assert!(log["error_code"].is_null(), "{log}");
    assert!(log["requested_at"].is_string(), "{log}");

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
        .wait_for_access_log(&format!("actor_name={scoped_name}"), |log| {
            log["method"] == "DELETE" && log["target"] == zone_path
        })
        .await;

    // A zone the role cannot see is a failure like any 404, so the log
    // cannot tell a scope that the zone exists.
    assert_eq!(hidden["result"], "failed", "{hidden}");
    assert_eq!(hidden["response_code"], "404", "{hidden}");

    let forbidden = app
        .wait_for_access_log(&format!("actor_name={scoped_name}&result=denied"), |log| {
            log["target"] == "/logs/access"
        })
        .await;

    assert_eq!(forbidden["response_code"], "403", "{forbidden}");
    assert_eq!(forbidden["error_code"], "FORBIDDEN", "{forbidden}");

    // Refused by the auth layer: 401, and no token verified to name.
    app.set_auth_token("not-a-token".to_string());

    let (status, body) = app.send_request(Method::GET, &zone_path, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = app.send_request(Method::GET, "/health", None).await;

    assert_eq!(status, StatusCode::OK, "{body}");

    app.set_auth_token(admin_token);

    let refused = app
        .wait_for_access_log("result=denied&source=api", |log| {
            log["target"] == zone_path && log["response_code"] == "401"
        })
        .await;

    assert!(refused["actor"].is_null(), "{refused}");
    assert_eq!(refused["error_code"], "INVALID_TOKEN", "{refused}");

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

        assert_eq!(log["response_code"], status, "{log}");
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
        "client_ip=localhost",
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

/// Verify that rejected body, query, and import values stay in client diagnostics,
/// while access rows keep only the error code and the zone stays unchanged.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn access_log_excludes_rejected_input_values() {
    let app = TestApp::start_local().await;
    let zone = app.create_test_zone().await;
    let zone_name = zone["name"].as_str().unwrap();
    let before = app.list_records(zone_name).await;
    let serial = app.read_zone_serial(zone_name).await;
    let body_marker = format!("{}-body-value", app.namespace());
    let query_marker = format!("{}-query-value", app.namespace());
    let import_marker = format!("{}-import-value", app.namespace());

    for (method, path, request, marker, code) in [
        (
            Method::POST,
            "/records".to_string(),
            Some(json!({
                "zone_name": zone_name,
                "name": "rejected",
                "type": "A",
                "value": body_marker,
            })),
            body_marker,
            "INVALID_RECORD_VALUE",
        ),
        (
            Method::GET,
            format!("/zones?sort={query_marker}"),
            None,
            query_marker,
            "INVALID_INPUT",
        ),
        (
            Method::POST,
            format!("/zones/{zone_name}/import"),
            Some(json!({ "content": "valid IN A 192.0.2.1\n", "mode": import_marker })),
            import_marker,
            "INVALID_INPUT",
        ),
    ] {
        let (status, body) = app.send_request(method.clone(), &path, request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        assert_eq!(body["code"], code, "{path}: {body}");
        assert!(
            body["error"].as_str().unwrap().contains(&marker),
            "{path}: {body}"
        );

        let target = path.split('?').next().unwrap();
        let log = app
            .wait_for_access_log("source=api&result=failed", |log| {
                log["method"] == method.as_str() && log["target"] == target
            })
            .await;

        assert!(
            !log.to_string().contains(&marker),
            "input reached the access log: {log}"
        );
        assert_eq!(log["error_code"], code, "{log}");
        assert_eq!(log["response_code"], "400", "{log}");
    }

    assert_eq!(app.list_records(zone_name).await, before);
    assert_eq!(app.read_zone_serial(zone_name).await, serial);
}

/// Verify the catalog and activity log expose committed changes from HTTP and the daemon socket.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn activity_log_lists_committed_operations_from_api_and_socket() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        openapi_enabled: true,
        ..Default::default()
    })
    .await;

    let (status, _) = app.send_request(Method::GET, "/logs/activity", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (actor, token) = app.create_api_token().await;
    app.set_auth_token(token);

    let (status, _) = app.send_request(Method::GET, "/operations", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, empty) = app
        .send_request(
            Method::GET,
            "/logs/activity?name=missing-activity-catalog&result=changed",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{empty}");
    assert_eq!(empty["items"], json!([]), "{empty}");
    assert_eq!(empty["pagination"]["total"], 0, "{empty}");
    let operations = empty["operations"].as_array().unwrap();
    assert!(operations.iter().all(Value::is_string), "{operations:?}");
    assert!(
        operations.contains(&json!("secondary.check")),
        "{operations:?}"
    );
    assert!(!operations.contains(&json!("zone.read")), "{operations:?}");
    assert!(
        !operations.contains(&json!("zone.import_many")),
        "{operations:?}"
    );

    let (status, spec) = app.send_request(Method::GET, "/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK, "{spec}");
    assert_eq!(
        spec["components"]["schemas"]["ActivityOperation"]["enum"],
        empty["operations"]
    );

    let (initial, offset) = list_activity_log(&app, "order=asc").await;
    assert!(
        initial
            .iter()
            .any(|item| item["operation"] == "token.create" && item["source"] == "socket"),
        "socket token creation should already be visible: {initial:?}"
    );

    let zone = app.zone_name("activity.example");
    let mut request = json!({
        "name": zone,
        "mname": format!("ns.{zone}"),
        "rname": format!("hostmaster@{zone}"),
        "dry_run": true,
    });
    let (status, preview) = app
        .send_request(Method::POST, "/zones", Some(request.clone()))
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["applied"], false);

    request["dry_run"] = json!(false);
    let (status, created) = app
        .send_request(Method::POST, "/zones", Some(request))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, record) = app
        .send_request(
            Method::POST,
            "/records",
            Some(json!({
                "zone_name": zone,
                "name": "www",
                "type": "A",
                "value": "192.0.2.61",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");

    let role = format!("{}-activity", app.namespace());
    app.run_cli_success(&["role", "create", &role], None).await;

    let mut ids = Vec::new();
    for (index, (operation, source, target)) in [
        ("zone.create", "api", json!({ "zone_name": zone })),
        (
            "record.create",
            "api",
            json!({
                "zone_name": zone,
                "record_id": record["record"]["id"],
                "record_type": "A",
            }),
        ),
        ("role.create", "socket", json!({ "name": role })),
    ]
    .into_iter()
    .enumerate()
    {
        let (items, total) = list_activity_log(
            &app,
            &format!(
                "result=changed&order=asc&offset={}&limit=1",
                offset + index as u64
            ),
        )
        .await;
        assert_eq!(total, offset + 3);
        assert_eq!(items.len(), 1, "{items:?}");
        let item = &items[0];
        assert_eq!(item["operation"], operation);
        assert_eq!(item["result"], "changed");
        assert_eq!(item["source"], source);
        let expected_actor = if source == "api" {
            json!({ "kind": "token", "name": actor })
        } else {
            Value::Null
        };
        assert_eq!(item["actor"], expected_actor);
        for (key, value) in target.as_object().unwrap() {
            assert_eq!(&item["target"][key], value, "{item}");
        }
        assert!(!item.to_string().contains("192.0.2.61"), "{item}");
        ids.push(item["id"].as_i64().unwrap());
    }

    let output = app
        .run_cli_success(
            &[
                "log", "activity", "--result", "changed", "--limit", "3", "-o", "json",
            ],
            None,
        )
        .await;
    let cli: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(cli["items"].as_array().unwrap().len(), 3, "{cli}");
    assert_eq!(
        cli["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        ids.into_iter().rev().collect::<Vec<_>>(),
    );
}
