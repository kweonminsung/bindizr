use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_are_created_listed_and_deleted_over_http() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        require_authentication: true,
        ..Default::default()
    })
    .await;
    // Bootstrap over the socket; everything after this is HTTP.
    let (bootstrap_name, bootstrap_token) = app.create_api_token().await;
    app.set_auth_token(bootstrap_token.clone());

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
        .request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": scoped_name, "description": "created over HTTP" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["token"]["name"], json!(scoped_name));
    assert_eq!(body["token"]["global"], false);
    let scoped_secret = body["token"]["token"]
        .as_str()
        .expect("create response carries the secret")
        .to_string();

    // The new token authenticates, and is scoped: no zone plane.
    app.set_auth_token(scoped_secret.clone());
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(zone_body(&app.zone_name("scoped-zone"))),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    app.set_auth_token(bootstrap_token.clone());
    let (status, body) = app
        .request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": global_name, "global": true })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["token"]["global"], true);
    let global_secret = body["token"]["token"].as_str().unwrap().to_string();

    // A global token minted over HTTP holds the zone plane.
    app.set_auth_token(global_secret);
    let (status, _) = app
        .request(
            Method::POST,
            "/zones",
            Some(zone_body(&app.zone_name("global-zone"))),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    app.set_auth_token(bootstrap_token.clone());
    let (status, body) = app.request(Method::GET, "/tokens", None).await;
    assert_eq!(status, StatusCode::OK);
    let tokens = body["tokens"].as_array().unwrap();
    for name in [&bootstrap_name, &scoped_name, &global_name] {
        assert!(
            tokens.iter().any(|token| token["name"] == json!(name)),
            "{name} missing from {body}"
        );
    }
    assert!(
        tokens.iter().all(|token| token.get("token").is_none()),
        "a listing must never carry a secret: {body}"
    );

    let (status, _) = app
        .request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": scoped_name })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Values the columns cannot hold are a 400, not a backend-dependent 500.
    let (status, _) = app
        .request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": app.zone_name("never"), "expires_in_days": i64::MAX })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = app
        .request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": app.zone_name("verbose"), "description": "x".repeat(256) })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .request(Method::DELETE, &format!("/tokens/{scoped_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // A deleted token stops authenticating at once.
    app.set_auth_token(scoped_secret);
    let (status, _) = app.request(Method::GET, "/zones", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    app.set_auth_token(bootstrap_token);
    let (status, _) = app
        .request(Method::DELETE, &format!("/tokens/{global_name}"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_cannot_manage_tokens() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        require_authentication: true,
        ..Default::default()
    })
    .await;
    let (_, global_token) = app.create_api_token().await;
    app.set_auth_token(global_token);
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, _) = app
        .request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": app.zone_name("escalation") })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app.request(Method::GET, "/tokens", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Not even its own.
    let (status, _) = app
        .request(Method::DELETE, &format!("/tokens/{scoped_name}"), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
