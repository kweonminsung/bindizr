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

#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    zones: (u16, String),
    records: (u16, String),
    changes: (u16, String),
    adjust: (u16, String),
}

struct MockUpstream {
    addr: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockUpstream {
    fn recorded(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

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
        "/external-dns/zones" => state.zones.clone(),
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

async fn spawn_mock(
    zones: (u16, Value),
    records: (u16, Value),
    changes: (u16, Value),
) -> MockUpstream {
    let not_mocked = (
        500,
        json!({"error": "adjust is not mocked", "code": "INTERNAL"}),
    );
    spawn_mock_with_adjust(zones, records, changes, not_mocked).await
}

async fn spawn_mock_with_adjust(
    zones: (u16, Value),
    records: (u16, Value),
    changes: (u16, Value),
    adjust: (u16, Value),
) -> MockUpstream {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        requests: requests.clone(),
        zones: (zones.0, zones.1.to_string()),
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

fn ok_mock_bodies() -> ((u16, Value), (u16, Value), (u16, Value)) {
    (
        (200, json!({"zones": ["example.com"]})),
        (200, json!({"records": []})),
        (
            200,
            json!({"changed_zones": ["example.com"], "records_added": 1, "records_deleted": 0}),
        ),
    )
}

async fn spawn_adapter(upstream_addr: std::net::SocketAddr, token: Option<&str>) -> String {
    let upstream = UpstreamClient::new(
        format!("http://{}", upstream_addr),
        token.map(str::to_string),
        2,
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

#[tokio::test]
async fn negotiate_forwards_bearer_token_and_returns_domain_filter() {
    let (zones, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(zones, records, changes).await;
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
    assert_eq!(recorded[0].0, "/external-dns/zones");
    assert_eq!(recorded[0].1.as_deref(), Some("Bearer test-token"));
}

#[tokio::test]
async fn negotiate_rejects_a_token_with_no_manageable_zones() {
    let (_, records, changes) = ok_mock_bodies();
    let mock = spawn_mock((200, json!({"zones": []})), records, changes).await;
    let base = spawn_adapter(mock.addr, Some("test-token")).await;

    let (status, _, body) = get(&base, Some(MEDIA_TYPE)).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("no manageable zones"));
}

#[tokio::test]
async fn negotiate_rejects_unsupported_accept_without_calling_bindizr() {
    let (zones, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(zones, records, changes).await;
    let base = spawn_adapter(mock.addr, None).await;

    let (status, _, _) = get(&base, Some("application/xml")).await;

    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
    assert!(mock.recorded().is_empty());
}

#[tokio::test]
async fn get_records_groups_rows_into_endpoints() {
    let records = json!({"records": [
        {"name": "app.example.com", "record_type": "A", "ttl": 300, "value": "192.0.2.2"},
        {"name": "app.example.com", "record_type": "A", "ttl": 300, "value": "192.0.2.1"},
        {"name": "app.example.com", "record_type": "TXT", "ttl": 3600,
         "value": "\"heritage=external-dns,external-dns/owner=default\""}
    ]});
    let mock = spawn_mock(
        (200, json!({"zones": []})),
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

#[tokio::test]
async fn apply_changes_posts_one_bindizr_change_set_and_returns_204() {
    let (zones, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(zones, records, changes).await;
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

#[tokio::test]
async fn apply_changes_rejects_invalid_input_without_calling_bindizr() {
    let (zones, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(zones, records, changes).await;
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

#[tokio::test]
async fn apply_changes_passes_bindizr_4xx_through_as_permanent_error() {
    let mock = spawn_mock(
        (200, json!({"zones": []})),
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

#[tokio::test]
async fn apply_changes_maps_bindizr_5xx_and_unreachable_to_retryable_502() {
    let mock = spawn_mock(
        (200, json!({"zones": []})),
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

#[tokio::test]
async fn adjustendpoints_forwards_rrsets_and_maps_the_servers_answer_back() {
    let (zones, records, changes) = ok_mock_bodies();
    let mock = spawn_mock_with_adjust(
        zones,
        records,
        changes,
        (
            200,
            json!({"rrsets": [
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
            {"dnsName": "a.example.com", "targets": ["2001:0DB8::1"], "recordType": "aaaa", "recordTTL": 300, "labels": {"owner": "default"}},
            {"dnsName": "b.example.com", "targets": ["v=spf1 -all"], "recordType": "TXT"}
        ]),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Identity fields stay the caller's; type/TTL/targets are the server's.
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
        json!({"rrsets": [
            {"name": "a.example.com", "record_type": "AAAA", "ttl": 300, "values": ["2001:0DB8::1"]},
            {"name": "b.example.com", "record_type": "TXT", "values": ["v=spf1 -all"]}
        ]})
    );
}

#[tokio::test]
async fn adjustendpoints_rejects_invalid_endpoints_before_the_round_trip() {
    let (zones, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(zones, records, changes).await;
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

#[tokio::test]
async fn healthz_reflects_bindizr_reachability() {
    let (zones, records, changes) = ok_mock_bodies();
    let mock = spawn_mock(zones, records, changes).await;

    let upstream = UpstreamClient::new(format!("http://{}", mock.addr), None, 2).unwrap();
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
