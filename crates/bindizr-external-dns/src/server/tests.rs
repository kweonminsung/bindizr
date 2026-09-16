use std::sync::{Arc, Mutex};

use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::{AppState, health_router, webhook_router};
use crate::{upstream::UpstreamClient, wire::MEDIA_TYPE};

/// One request the mock bindizr server saw: path, Authorization header, body.
type RecordedRequest = (String, Option<String>, String);

/// The mock bindizr server's canned responses and the requests it recorded.
#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    domains: (u16, String),
    records: (u16, String),
    changes: (u16, String),
    adjust: (u16, String),
}

/// A running mock bindizr server: its address and the requests it saw.
struct MockUpstream {
    addr: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockUpstream {
    /// Return requests captured by the mock upstream server.
    fn recorded(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

/// Record a mock upstream request and return its configured response.
async fn mock_handler(State(state): State<MockState>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = axum::body::to_bytes(request.into_body(), usize::MAX)
        .await
        .unwrap();
    state.requests.lock().unwrap().push((
        path.clone(),
        authorization,
        String::from_utf8_lossy(&body).to_string(),
    ));

    let (status, body) = match path.as_str() {
        "/external-dns/domains" => state.domains.clone(),
        "/external-dns/records" => state.records.clone(),
        "/external-dns/changes" => state.changes.clone(),
        "/external-dns/adjust" => state.adjust.clone(),
        "/health" => (200, r#"{"status":"healthy"}"#.to_string()),
        _ => (
            404,
            r#"{"error":"not found","code":"NOT_FOUND"}"#.to_string(),
        ),
    };
    (
        StatusCode::from_u16(status).unwrap(),
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// Start a mock upstream with domain, record, and change responses.
async fn spawn_mock(
    domains: (u16, Value),
    records: (u16, Value),
    changes: (u16, Value),
) -> MockUpstream {
    let not_mocked = (
        500,
        json!({"error": "adjust is not mocked", "code": "INTERNAL"}),
    );
    spawn_mock_with_adjust(domains, records, changes, not_mocked).await
}

/// Start a mock upstream including an endpoint-adjustment response.
async fn spawn_mock_with_adjust(
    domains: (u16, Value),
    records: (u16, Value),
    changes: (u16, Value),
    adjust: (u16, Value),
) -> MockUpstream {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        requests: requests.clone(),
        domains: (domains.0, domains.1.to_string()),
        records: (records.0, records.1.to_string()),
        changes: (changes.0, changes.1.to_string()),
        adjust: (adjust.0, adjust.1.to_string()),
    };
    let router = axum::Router::new().fallback(mock_handler).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    MockUpstream { addr, requests }
}

/// Build successful domain, record, and change response fixtures.
fn ok_mock_bodies() -> ((u16, Value), (u16, Value), (u16, Value)) {
    (
        (200, json!({"domains": ["example.com"]})),
        (200, json!({"records": []})),
        (
            200,
            json!({"changed_zones": ["example.com"], "records_added": 1, "records_deleted": 0}),
        ),
    )
}

/// Start a webhook adapter connected to the test upstream.
async fn spawn_adapter(upstream_addr: std::net::SocketAddr, token: Option<&str>) -> String {
    let upstream = UpstreamClient::new(
        format!("http://{}", upstream_addr),
        token.map(str::to_string),
        2,
        None,
    )
    .unwrap();
    let state = Arc::new(AppState { upstream });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let webhook = webhook_router(state);
    tokio::spawn(async move {
        axum::serve(listener, webhook).await.unwrap();
    });
    format!("http://{}", addr)
}

/// Send a webhook GET request with the requested Accept header.
async fn get(url: &str, accept: Option<&str>) -> (StatusCode, Option<String>, String) {
    let client = reqwest::Client::new();
    let mut request = client.get(url);
    if let Some(accept) = accept {
        request = request.header(header::ACCEPT, accept);
    }
    let response = request.send().await.unwrap();
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (status, content_type, response.text().await.unwrap())
}

/// Send a JSON webhook POST request and collect the response.
async fn post(url: &str, body: Value) -> (StatusCode, String) {
    let response = reqwest::Client::new()
        .post(url)
        .header(header::CONTENT_TYPE, MEDIA_TYPE)
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    (status, response.text().await.unwrap())
}

/// Verify that negotiate forwards bearer token and returns domain filter.
#[tokio::test]
async fn negotiate_forwards_bearer_token_and_returns_domain_filter() {
    let (domains, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(domains, records, changes).await;
    let base = spawn_adapter(mock.addr, Some("test-token")).await;

    let (status, content_type, body) = get(&base, Some(MEDIA_TYPE)).await;

    assert_eq!(status, StatusCode::OK);
    // external-dns compares the negotiation Content-Type byte-for-byte.
    assert_eq!(content_type.as_deref(), Some(MEDIA_TYPE));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"include": ["example.com"]})
    );

    let recorded = mock.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, "/external-dns/domains");
    assert_eq!(recorded[0].1.as_deref(), Some("Bearer test-token"));
}

/// Verify that `negotiate` rejects a token with no manageable names.
#[tokio::test]
async fn negotiate_rejects_a_token_with_no_manageable_names() {
    let (_, records, changes) = ok_mock_bodies();
    let mock = spawn_mock((200, json!({"domains": []})), records, changes).await;
    let base = spawn_adapter(mock.addr, Some("test-token")).await;

    let (status, _, body) = get(&base, Some(MEDIA_TYPE)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("no manageable names"));
}

/// Verify that `negotiate` rejects unsupported accept without calling bindizr.
#[tokio::test]
async fn negotiate_rejects_unsupported_accept_without_calling_bindizr() {
    let (domains, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(domains, records, changes).await;
    let base = spawn_adapter(mock.addr, None).await;

    let (status, _, _) = get(&base, Some("application/xml")).await;

    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
    assert!(mock.recorded().is_empty());
}

/// Verify that `list_records` maps records to endpoints.
#[tokio::test]
async fn list_records_maps_records_to_endpoints() {
    let records = json!({"records": [
        {"name": "app.example.com", "record_type": "A", "ttl": 300,
         "values": ["192.0.2.1", "192.0.2.2"]},
        {"name": "app.example.com", "record_type": "TXT", "ttl": 3600,
         "values": ["\"heritage=external-dns,external-dns/owner=default\""]}
    ]});
    let mock = spawn_mock(
        (200, json!({"domains": []})),
        (200, records),
        (200, json!({})),
    )
    .await;
    let base = spawn_adapter(mock.addr, Some("test-token")).await;

    let (status, content_type, body) = get(&format!("{}/records", base), Some(MEDIA_TYPE)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some(MEDIA_TYPE));
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!([
            {"dnsName": "app.example.com", "targets": ["192.0.2.1", "192.0.2.2"],
             "recordType": "A", "recordTTL": 300},
            {"dnsName": "app.example.com",
             "targets": ["\"heritage=external-dns,external-dns/owner=default\""],
             "recordType": "TXT", "recordTTL": 3600}
        ])
    );
}

/// Verify that apply changes posts one bindizr change set and returns 204.
#[tokio::test]
async fn apply_changes_posts_one_bindizr_change_set_and_returns_204() {
    let (domains, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(domains, records, changes).await;
    let base = spawn_adapter(mock.addr, Some("test-token")).await;

    let (status, _) = post(
        &format!("{}/records", base),
        json!({
            "create": [{"dnsName": "a.example.com", "targets": ["192.0.2.1"],
                        "recordType": "A", "recordTTL": 300}],
            "updateOld": [{"dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A"}],
            "updateNew": [{"dnsName": "b.example.com", "targets": ["192.0.2.3"], "recordType": "A"}],
            "delete": [{"dnsName": "c.example.com", "targets": ["\"v=1\""], "recordType": "TXT"}]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    let recorded = mock.recorded();
    assert_eq!(
        recorded.len(),
        1,
        "one webhook call must become one bindizr call"
    );
    assert_eq!(recorded[0].0, "/external-dns/changes");
    assert_eq!(recorded[0].1.as_deref(), Some("Bearer test-token"));
    assert_eq!(
        serde_json::from_str::<Value>(&recorded[0].2).unwrap(),
        json!({
            "creates": [{"name": "a.example.com", "record_type": "A", "ttl": 300,
                         "values": ["192.0.2.1"]}],
            "updates": [{"old": {"name": "b.example.com", "record_type": "A",
                                 "values": ["192.0.2.2"]},
                         "new": {"name": "b.example.com", "record_type": "A",
                                 "values": ["192.0.2.3"]}}],
            "deletes": [{"name": "c.example.com", "record_type": "TXT",
                         "values": ["\"v=1\""]}]
        })
    );
}

/// Verify that `apply_changes` rejects invalid input without calling bindizr.
#[tokio::test]
async fn apply_changes_rejects_invalid_input_without_calling_bindizr() {
    let (domains, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(domains, records, changes).await;
    let base = spawn_adapter(mock.addr, None).await;

    let (status, body) = post(
        &format!("{}/records", base),
        json!({"create": [{"dnsName": "a.example.com", "targets": ["x"], "recordType": "SRV"}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("not supported"));

    let (status, _) = post(&format!("{}/records", base), json!({"create": "nope"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert!(mock.recorded().is_empty());
}

/// Verify that `apply_changes` passes bindizr 4xx through as permanent error.
#[tokio::test]
async fn apply_changes_passes_bindizr_4xx_through_as_permanent_error() {
    let mock = spawn_mock(
        (200, json!({"domains": []})),
        (200, json!({"records": []})),
        (
            403,
            json!({"error": "Zone 'internal.example.com' is not enabled for ExternalDNS", "code": "FORBIDDEN"}),
        ),
    )
    .await;
    let base = spawn_adapter(mock.addr, Some("test-token")).await;

    let (status, body) = post(
        &format!("{}/records", base),
        json!({"create": [{"dnsName": "api.internal.example.com", "targets": ["192.0.2.1"], "recordType": "A"}]}),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("not enabled for ExternalDNS"));
}

/// Verify that `apply_changes` maps bindizr 5xx and unreachable to retryable 502.
#[tokio::test]
async fn apply_changes_maps_bindizr_5xx_and_unreachable_to_retryable_502() {
    let mock = spawn_mock(
        (200, json!({"domains": []})),
        (200, json!({"records": []})),
        (
            500,
            json!({"error": "Failed to apply ExternalDNS changes", "code": "INTERNAL"}),
        ),
    )
    .await;
    let base = spawn_adapter(mock.addr, Some("test-token")).await;
    let changes = json!({"create": [{"dnsName": "a.example.com", "targets": ["192.0.2.1"], "recordType": "A"}]});

    let (status, _) = post(&format!("{}/records", base), changes.clone()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // A closed upstream port maps to the same retryable 502.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed.local_addr().unwrap();
    drop(closed);
    let base = spawn_adapter(closed_addr, Some("test-token")).await;
    let (status, _) = post(&format!("{}/records", base), changes).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

/// Verify that adjustendpoints forwards records and returns merged endpoints.
#[tokio::test]
async fn adjustendpoints_forwards_records_and_returns_merged_endpoints() {
    let (domains, records, changes) = ok_mock_bodies();
    let mock = spawn_mock_with_adjust(
        domains,
        records,
        changes,
        (
            200,
            json!({"records": [
                {"name": "a.example.com", "record_type": "AAAA", "ttl": 300, "values": ["2001:db8::1"]},
                {"name": "b.example.com", "record_type": "TXT", "values": ["\"v=spf1 -all\""]}
            ]}),
        ),
    )
    .await;
    let base = spawn_adapter(mock.addr, None).await;

    let (status, body) = post(
        &format!("{}/adjustendpoints", base),
        json!([
            {"dnsName": "a.example.com", "targets": ["2001:0DB8::1"], "recordType": "aaaa", "recordTTL": 300, "labels": {"owner": "default"},
             "providerSpecific": [{"name": "webhook/flag", "value": "on"}]},
            {"dnsName": "b.example.com", "targets": ["v=spf1 -all"], "recordType": "TXT"}
        ]),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Identity (dnsName, labels) stays the caller's, type/TTL/targets are
    // the server's, and provider-specific properties are dropped.
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!([
            {"dnsName": "a.example.com", "targets": ["2001:db8::1"], "recordType": "AAAA", "recordTTL": 300, "labels": {"owner": "default"}},
            {"dnsName": "b.example.com", "targets": ["\"v=spf1 -all\""], "recordType": "TXT"}
        ])
    );

    let recorded = mock.recorded();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, "/external-dns/adjust");
    assert_eq!(
        serde_json::from_str::<Value>(&recorded[0].2).unwrap(),
        json!({"records": [
            {"name": "a.example.com", "record_type": "AAAA", "ttl": 300, "values": ["2001:0DB8::1"]},
            {"name": "b.example.com", "record_type": "TXT", "values": ["v=spf1 -all"]}
        ]})
    );
}

/// Verify that adjustendpoints rejects invalid endpoints without calling bindizr.
#[tokio::test]
async fn adjustendpoints_rejects_invalid_endpoints_without_calling_bindizr() {
    let (domains, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(domains, records, changes).await;
    let base = spawn_adapter(mock.addr, None).await;

    let (status, body) = post(
        &format!("{}/adjustendpoints", base),
        json!([{"dnsName": "a.example.com", "targets": ["192.0.2.1"], "recordType": "A", "setIdentifier": "weighted"}]),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("setIdentifier"));
    assert!(mock.recorded().is_empty());
}

/// Verify that healthz reflects bindizr reachability.
#[tokio::test]
async fn healthz_reflects_bindizr_reachability() {
    let (domains, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(domains, records, changes).await;

    let upstream = UpstreamClient::new(format!("http://{}", mock.addr), None, 2, None).unwrap();
    let state = Arc::new(AppState { upstream });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let health = health_router(state);
    tokio::spawn(async move {
        axum::serve(listener, health).await.unwrap();
    });

    let (status, _, body) = get(&format!("http://{}/healthz", addr), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");

    let (status, _, body) = get(&format!("http://{}/metrics", addr), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("bindizr_external_dns_requests_total"));
}

/// Verify that endpoint label tracks head with get and skips unrouted methods.
#[test]
fn endpoint_label_tracks_head_with_get_and_skips_unrouted_methods() {
    use axum::http::Method;

    use super::endpoint_label;

    assert_eq!(endpoint_label(&Method::HEAD, "/"), Some("negotiate"));
    assert_eq!(
        endpoint_label(&Method::HEAD, "/records"),
        Some("records_get")
    );
    assert_eq!(
        endpoint_label(&Method::POST, "/adjustendpoints"),
        Some("adjustendpoints")
    );
    // An unsupported method 405s without a handler; it must not count.
    assert_eq!(endpoint_label(&Method::DELETE, "/records"), None);
}
