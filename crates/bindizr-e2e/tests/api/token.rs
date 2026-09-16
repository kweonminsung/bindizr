use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

/// Verify that tokens are created listed and deleted over HTTP.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_are_created_listed_and_deleted_over_http() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    // The first token comes over the socket; everything after this is HTTP.
    let (first_token_name, first_token) = app.create_api_token().await;
    app.set_auth_token(first_token.clone());

    // The zone-name prefix keeps token names unique in compose mode.
    let scoped_name = app.zone_name("http-scoped");
    let global_name = app.zone_name("http-global");
    let zone_body = |name: &str| {
        json!({
            "name": name,
            "mname": format!("ns1.{name}"),
            "rname": "admin@example.com",
            "default_ttl": 3600,
        })
    };

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": scoped_name, "description": "created over HTTP" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["token"]["name"], json!(scoped_name));
    assert_eq!(body["token"]["global"], false);
    let scoped_secret = body["secret"]
        .as_str()
        .expect("create response carries the secret")
        .to_string();

    // The new token authenticates, and is scoped: no zone plane.
    app.set_auth_token(scoped_secret.clone());
    let (status, _) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(zone_body(&app.zone_name("scoped-zone"))),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    app.set_auth_token(first_token.clone());
    let (status, body) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": global_name, "global": true })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["token"]["global"], true);
    let global_secret = body["secret"].as_str().unwrap().to_string();

    // A global token minted over HTTP holds the zone plane.
    app.set_auth_token(global_secret);
    let (status, _) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(zone_body(&app.zone_name("global-zone"))),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    app.set_auth_token(first_token.clone());
    let (status, body) = app.send_request(Method::GET, "/tokens", None).await;
    assert_eq!(status, StatusCode::OK);
    let tokens = body["items"].as_array().unwrap();
    for name in [&first_token_name, &scoped_name, &global_name] {
        assert!(
            tokens.iter().any(|token| token["name"] == json!(name)),
            "{name} missing from {body}"
        );
    }
    assert!(
        tokens.iter().all(|token| token.get("secret").is_none()),
        "a listing must never carry a secret: {body}"
    );
    // Every listing pages the same way, management tables included.
    let total = body["pagination"]["total"].as_u64().unwrap();
    assert!(total >= 3, "{body}");

    let (status, body) = app
        .send_request(Method::GET, "/tokens?limit=1&offset=1", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["pagination"]["limit"], 1, "{body}");
    assert_eq!(body["pagination"]["offset"], 1, "{body}");
    assert_eq!(body["pagination"]["total"], total, "{body}");

    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": scoped_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Values the columns cannot hold are a 400, not a backend-dependent 500.
    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": app.zone_name("never"), "expires_in_days": i64::MAX })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": app.zone_name("verbose"), "description": "x".repeat(256) })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .send_request(Method::DELETE, &format!("/tokens/{scoped_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // A deleted token stops authenticating at once.
    app.set_auth_token(scoped_secret);
    let (status, _) = app.send_request(Method::GET, "/zones", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    app.set_auth_token(first_token);
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/tokens/{global_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Verify that scoped token cannot manage tokens.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_cannot_manage_tokens() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": app.zone_name("escalation") })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app.send_request(Method::GET, "/tokens", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Not even its own.
    let (status, _) = app
        .send_request(Method::DELETE, &format!("/tokens/{scoped_name}"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Verify that tokens self describes the bearer.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_self_describes_the_bearer() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (global_name, global_token) = app.create_api_token().await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;

    for (name, token, global) in [
        (global_name, global_token, true),
        (scoped_name, scoped_token, false),
    ] {
        app.set_auth_token(token);
        let (status, body) = app.send_request(Method::GET, "/tokens/self", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["token"]["name"], json!(name));
        assert_eq!(body["token"]["global"], json!(global));
        assert!(body.get("secret").is_none(), "{body}");
    }
}

/// Verify that tokens self needs a token even with authentication off.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_self_needs_a_token_even_with_authentication_off() {
    let app = TestApp::start_with_options(TestAppOptions {
        authentication_required: false,
        ..Default::default()
    })
    .await;

    for path in ["/tokens/self", "/tokens/self/grants"] {
        let (status, _) = app.send_request(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
}

/// Verify that `api.authentication.initial_token` seeds the first global token.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn the_configured_initial_token_authenticates_without_the_cli() {
    let secret = "an-initial-token-secret";
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        initial_token: Some(secret.to_string()),
        ..Default::default()
    })
    .await;

    // Nothing ran the CLI, so this token exists only because the config named it.
    app.set_auth_token(secret.to_string());
    let (status, body) = app.send_request(Method::GET, "/tokens", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|token| token["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"initial"), "{names:?}");

    let (status, _) = app.send_request(Method::GET, "/tokens/self", None).await;
    assert_eq!(status, StatusCode::OK);

    app.set_auth_token("not-the-initial-token".to_string());
    let (status, _) = app.send_request(Method::GET, "/tokens", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
