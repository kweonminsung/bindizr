use serde_json::json;

use super::*;

/// Build an external-dns endpoint fixture with the supplied targets.
fn endpoint(dns_name: &str, record_type: &str, ttl: i64, targets: &[&str]) -> Endpoint {
    Endpoint {
        dns_name: dns_name.to_string(),
        record_type: record_type.to_string(),
        record_ttl: ttl,
        targets: targets.iter().map(ToString::to_string).collect(),
        ..Default::default()
    }
}

/// Verify that endpoint fields deserialize using the names and casing of ExternalDNS v0.21.0
/// JSON tags.
#[test]
fn endpoint_deserializes_external_dns_wire_format() {
    let parsed: Endpoint = serde_json::from_value(json!({
        "dnsName": "app.example.com",
        "targets": ["192.0.2.10"],
        "recordType": "A",
        "recordTTL": 300,
        "labels": { "owner": "default" },
        "providerSpecific": [{ "name": "x", "value": "y" }]
    }))
    .unwrap();

    assert_eq!(parsed.dns_name, "app.example.com");
    assert_eq!(parsed.targets, ["192.0.2.10"]);
    assert_eq!(parsed.record_type, "A");
    assert_eq!(parsed.record_ttl, 300);
    assert_eq!(
        parsed.labels.get("owner").map(String::as_str),
        Some("default")
    );
    assert_eq!(parsed.provider_specific[0].name, "x");
}

/// Verify that endpoint serializes with omitempty semantics.
#[test]
fn endpoint_serializes_with_omitempty_semantics() {
    let serialized =
        serde_json::to_value(endpoint("app.example.com", "A", 300, &["192.0.2.10"])).unwrap();

    assert_eq!(
        serialized,
        json!({
            "dnsName": "app.example.com",
            "targets": ["192.0.2.10"],
            "recordType": "A",
            "recordTTL": 300
        })
    );

    // TTL 0 means "not configured" and is omitted, like Go's omitempty.
    let serialized =
        serde_json::to_value(endpoint("app.example.com", "A", 0, &["192.0.2.10"])).unwrap();

    assert!(serialized.get("recordTTL").is_none());
}

/// Verify that endpoint validation refuses only a `setIdentifier`, leaving
/// every record rule to the server.
#[test]
fn endpoint_validation_refuses_only_a_set_identifier() {
    let mut with_set_id = endpoint("a.example.com", "A", 0, &["192.0.2.1"]);
    with_set_id.set_identifier = "weighted".to_string();

    assert_eq!(
        BindizrRecord::try_from(&with_set_id),
        Err(ValidateEndpointError::SetIdentifier)
    );

    // The server answers these with a 400 the adapter passes through.
    for forwarded in [
        endpoint("", "A", 0, &["192.0.2.1"]),
        endpoint("a.example.com", "SRV", 0, &["x"]),
        endpoint("a.example.com", "A", 0, &[]),
        endpoint("a.example.com", "CNAME", 0, &["a.", "b."]),
        endpoint("a.example.com", "A", -1, &["192.0.2.1"]),
    ] {
        assert!(BindizrRecord::try_from(&forwarded).is_ok(), "{forwarded:?}");
    }
}

/// Verify that changes to bindizr pairs updates and maps TTL.
#[test]
fn changes_to_bindizr_pairs_updates_and_maps_ttl() {
    let changes: Changes = serde_json::from_value(json!({
        "create": [{ "dnsName": "a.example.com", "targets": ["192.0.2.1"], "recordType": "A", "recordTTL": 300 }],
        "updateOld": [{ "dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A" }],
        "updateNew": [{ "dnsName": "b.example.com", "targets": ["192.0.2.3"], "recordType": "A" }]
    }))
    .unwrap();

    let request = ApplyExternalDnsChangesRequest::try_from(&changes).unwrap();

    assert_eq!(request.creates.len(), 1);
    assert_eq!(request.creates[0].ttl, Some(300));
    assert_eq!(request.updates.len(), 1);

    // TTL 0 (unset) maps to None so the server applies the zone TTL.
    assert_eq!(request.updates[0].old.ttl, None);
    assert_eq!(request.updates[0].new.values, ["192.0.2.3"]);
    assert!(request.deletes.is_empty());
}

/// Verify that changes to bindizr rejects mismatched update pairs.
#[test]
fn changes_to_bindizr_rejects_mismatched_update_pairs() {
    let changes: Changes = serde_json::from_value(json!({
        "updateOld": [{ "dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A" }],
        "updateNew": []
    }))
    .unwrap();

    assert!(ApplyExternalDnsChangesRequest::try_from(&changes).is_err());
}

/// Verify that adjustment refuses an answer that cannot be paired by position.
#[test]
fn adjusted_endpoints_require_one_record_per_endpoint() {
    let original = endpoint("a.example.com", "A", 300, &["192.0.2.1"]);
    let record = BindizrRecord::try_from(&original).unwrap();

    assert_eq!(
        build_adjusted_endpoints(vec![original.clone()], vec![]),
        Err(AdjustedRecordCountError {
            records: 0,
            endpoints: 1
        })
    );
    assert_eq!(
        build_adjusted_endpoints(vec![original], vec![record.clone(), record]),
        Err(AdjustedRecordCountError {
            records: 2,
            endpoints: 1
        })
    );
}

/// Verify that ExternalDNS's zero TTL is sent as unset and every other value
/// as given, for the server to range-check.
#[test]
fn endpoint_ttl_sends_zero_as_unset_and_the_rest_as_given() {
    for ttl in [0i64, -1, 2_147_483_648, i64::from(u32::MAX) + 1] {
        let changes: Changes = serde_json::from_value(json!({ "create": [{ "dnsName": "ttl.example.com", "targets": ["192.0.2.1"], "recordType": "A", "recordTTL": ttl }] })).unwrap();
        let request = ApplyExternalDnsChangesRequest::try_from(&changes).unwrap();
        assert_eq!(request.creates[0].ttl, (ttl != 0).then_some(ttl));
    }
}
