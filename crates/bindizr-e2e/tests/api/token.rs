use reqwest::{Method, StatusCode};
use serde_json::json;

use crate::common::{TestApp, TestAppOptions};

/// Verify that tokens are created listed and deleted over HTTP.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_support_create_list_and_delete_over_http() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;

    // The first token comes over the socket; everything after this is HTTP.
    let (first_token_name, first_token) = app.create_api_token().await;
    app.set_auth_token(first_token.clone());

    // The zone-name prefix keeps token and role names unique in compose mode.
    let scoped_name = app.zone_name("http-scoped");
    let admin_name = app.zone_name("http-admin");
    let zone_body = |name: &str| {
        json!({
            "name": name,
            "mname": format!("ns1.{name}"),
            "rname": "admin@example.com",
            "default_ttl": 3600,
        })
    };

    // A token needs a role that exists.
    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": scoped_name, "role_name": scoped_name })),
        )
        .await;

    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = app
        .send_request(Method::POST, "/roles", Some(json!({ "name": scoped_name })))
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({
                "name": scoped_name,
                "role_name": scoped_name,
                "description": "created over HTTP",
            })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["token"]["name"], json!(scoped_name));
    assert_eq!(body["token"]["role_name"], json!(scoped_name));
    let scoped_secret = body["secret"]
        .as_str()
        .expect("create response carries the secret")
        .to_string();

    // The new token authenticates, and its role holds no grant yet.
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
            Some(json!({ "name": admin_name, "role_name": "admin" })),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["token"]["role_name"], "admin");
    let admin_secret = body["secret"].as_str().unwrap().to_string();

    // A token in the built-in role minted over HTTP may create zones.
    app.set_auth_token(admin_secret);

    let (status, _) = app
        .send_request(
            Method::POST,
            "/zones",
            Some(zone_body(&app.zone_name("admin-zone"))),
        )
        .await;

    assert_eq!(status, StatusCode::CREATED);

    app.set_auth_token(first_token.clone());

    let (status, body) = app.send_request(Method::GET, "/tokens", None).await;

    assert_eq!(status, StatusCode::OK);
    let tokens = body["items"].as_array().unwrap();

    for name in [&first_token_name, &scoped_name, &admin_name] {
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
            Some(json!({ "name": scoped_name, "role_name": "admin" })),
        )
        .await;

    assert_eq!(status, StatusCode::CONFLICT);

    // Values the columns cannot hold are a 400, not a backend-dependent 500.
    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({
                "name": app.zone_name("never"),
                "role_name": "admin",
                "expires_in_days": i64::MAX,
            })),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({
                "name": app.zone_name("verbose"),
                "role_name": "admin",
                "description": "x".repeat(256),
            })),
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
        .send_request(Method::DELETE, &format!("/tokens/{admin_name}"), None)
        .await;

    assert_eq!(status, StatusCode::OK);
}

/// Verify that a token whose role lacks `access:manage` cannot manage tokens or roles.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn scoped_token_rejects_token_management() {
    let mut app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, admin_token) = app.create_api_token().await;
    app.set_auth_token(admin_token);

    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;
    app.set_auth_token(scoped_token);

    let (status, _) = app
        .send_request(
            Method::POST,
            "/tokens",
            Some(json!({ "name": app.zone_name("escalation"), "role_name": "admin" })),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .send_request(
            Method::POST,
            &format!("/roles/{scoped_name}/grants"),
            Some(json!({ "actions": ["access:manage"] })),
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
    let (admin_name, admin_token) = app.create_api_token().await;
    let (scoped_name, scoped_token) = app.create_scoped_api_token().await;

    for (name, token, role) in [
        (admin_name, admin_token, "admin".to_string()),
        (scoped_name.clone(), scoped_token, scoped_name),
    ] {
        app.set_auth_token(token);
        let (status, body) = app.send_request(Method::GET, "/tokens/self", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["token"]["name"], json!(name));
        assert_eq!(body["token"]["role_name"], json!(role));
        assert!(body.get("secret").is_none(), "{body}");
    }
}

/// Verify that a browser on another origin may send its token: the preflight
/// names `Authorization`, which the Fetch standard never lets `*` stand for.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn cors_preflight_allows_the_authorization_header() {
    let app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let response = reqwest::Client::new()
        .request(Method::OPTIONS, format!("{}/zones", app.base_url()))
        .header("origin", "https://ui.example")
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "authorization, content-type",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    let allowed = response.headers()["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .to_ascii_lowercase();

    assert!(allowed.contains("authorization"), "{allowed}");
    assert!(allowed.contains("content-type"), "{allowed}");
}

/// Verify that tokens self has no token to describe with authentication off:
/// 404 rather than a 401 no challenge could satisfy (RFC 9110, Section 15.5.2).
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn tokens_self_has_no_token_when_authentication_is_disabled() {
    let app = TestApp::start_with_options(TestAppOptions {
        authentication_required: false,
        ..Default::default()
    })
    .await;

    for path in ["/tokens/self", "/tokens/self/grants"] {
        let response = reqwest::Client::new()
            .get(format!("{}{path}", app.base_url()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(
            !response.headers().contains_key("www-authenticate"),
            "{path}"
        );

        let body: serde_json::Value = response.json().await.unwrap();

        assert_eq!(body["code"], "TOKEN_NOT_FOUND", "{body}");
    }
}

/// Authenticate equivalent schemes and SP separators without changing token bytes.
#[tokio::test]
#[serial_test::serial(bindizr_e2e)]
async fn bearer_authentication_obeys_http_grammar_and_challenges_failures() {
    let app = TestApp::start_with_options(TestAppOptions {
        authentication_required: true,
        ..Default::default()
    })
    .await;
    let (_, token) = app.create_api_token().await;

    let client = reqwest::Client::new();

    for prefix in ["Bearer ", "bearer ", "BEARER ", "bEaReR   "] {
        let response = client
            .get(format!("{}/tokens/self", app.base_url()))
            .header("authorization", format!("{prefix}{token}"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "{prefix:?}");
        assert!(!response.headers().contains_key("www-authenticate"));
    }

    for authorization in [
        None,
        Some("Basic ignored".to_string()),
        Some("Bearer".to_string()),
        Some("Bearer   ".to_string()),
        Some(format!("Bearer\t{token}")),
        Some(format!("Bearer invalid-{token}")),
        Some(format!("Bearer {token} extra")),
    ] {
        let mut request = client.get(format!("{}/tokens/self", app.base_url()));

        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }

        let response = request.send().await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // RFC 6750, Section 3: the challenge names a realm, and the error
        // code only once a token was presented and refused.
        let challenge = response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .to_string();

        let body: serde_json::Value = response.json().await.unwrap();

        match body["code"].as_str() {
            Some("UNAUTHORIZED") => assert_eq!(challenge, "Bearer realm=\"bindizr\"", "{body}"),
            Some("INVALID_TOKEN") => assert_eq!(
                challenge, "Bearer realm=\"bindizr\", error=\"invalid_token\"",
                "{body}"
            ),
            other => panic!("unexpected code {other:?}: {body}"),
        }
    }
}
