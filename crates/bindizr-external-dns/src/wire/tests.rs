use serde_json::json;

use super::{Changes, Endpoint};

fn endpoint(dns_name: &str, record_type: &str, ttl: i64, targets: &[&str]) -> Endpoint {
    Endpoint {
        dns_name: dns_name.to_string(),
        record_type: record_type.to_string(),
        record_ttl: ttl,
        targets: targets.iter().map(|t| t.to_string()).collect(),
        ..Endpoint::default()
    }
}

// Field names and casing are the v0.21.0 endpoint.Endpoint json tags.
#[test]
fn endpoint_deserializes_external_dns_wire_format() {
    let parsed: Endpoint = serde_json::from_value(json!({
        "dnsName": "app.example.com",
        "targets": ["192.0.2.10"],
        "recordType": "A",
        "recordTTL": 300,
        "labels": {"owner": "default"},
        "providerSpecific": [{"name": "x", "value": "y"}]
    }))
    .unwrap();

    assert_eq!(parsed.dns_name, "app.example.com");
    assert_eq!(parsed.targets, vec!["192.0.2.10"]);
    assert_eq!(parsed.record_type, "A");
    assert_eq!(parsed.record_ttl, 300);
    assert_eq!(
        parsed.labels.get("owner").map(String::as_str),
        Some("default")
    );
    assert_eq!(parsed.provider_specific[0].name, "x");
}

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

#[test]
fn endpoint_validate_rejects_unsupported_shapes() {
    assert!(endpoint("", "A", 0, &["192.0.2.1"]).validate().is_err());
    assert!(
        endpoint("a.example.com", "NS", 0, &["x"])
            .validate()
            .is_err()
    );
    assert!(
        endpoint("a.example.com", "MX", 0, &["x"])
            .validate()
            .is_err()
    );
    assert!(endpoint("a.example.com", "A", 0, &[]).validate().is_err());
    assert!(endpoint("a.example.com", "A", 0, &[""]).validate().is_err());
    assert!(
        endpoint("a.example.com", "CNAME", 0, &["a.", "b."])
            .validate()
            .is_err()
    );
    assert!(
        endpoint("a.example.com", "A", -1, &["192.0.2.1"])
            .validate()
            .is_err()
    );

    let mut with_set_id = endpoint("a.example.com", "A", 0, &["192.0.2.1"]);
    with_set_id.set_identifier = "weighted".to_string();
    assert!(with_set_id.validate().is_err());

    assert!(
        endpoint("a.example.com", "a", 300, &["192.0.2.1"])
            .validate()
            .is_ok()
    );

    // Whitespace-only content is valid TXT rdata but garbage for other types.
    assert!(
        endpoint("a.example.com", "A", 0, &["   "])
            .validate()
            .is_err()
    );
    assert!(
        endpoint("t.example.com", "TXT", 0, &["   "])
            .validate()
            .is_ok()
    );
}

#[test]
fn changes_to_bindizr_pairs_updates_and_maps_ttl() {
    let changes: Changes = serde_json::from_value(json!({
        "create": [{"dnsName": "a.example.com", "targets": ["192.0.2.1"], "recordType": "A", "recordTTL": 300}],
        "updateOld": [{"dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A"}],
        "updateNew": [{"dnsName": "b.example.com", "targets": ["192.0.2.3"], "recordType": "A"}]
    }))
    .unwrap();

    let bindizr = changes.to_bindizr().unwrap();

    assert_eq!(bindizr.creates.len(), 1);
    assert_eq!(bindizr.creates[0].ttl, Some(300));
    assert_eq!(bindizr.updates.len(), 1);
    // TTL 0 (unset) maps to None so the server applies the zone TTL.
    assert_eq!(bindizr.updates[0].old.ttl, None);
    assert_eq!(bindizr.updates[0].new.values, vec!["192.0.2.3"]);
    assert!(bindizr.deletes.is_empty());
}

#[test]
fn changes_to_bindizr_rejects_mismatched_update_pairs() {
    let changes: Changes = serde_json::from_value(json!({
        "updateOld": [{"dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A"}],
        "updateNew": []
    }))
    .unwrap();

    assert!(changes.to_bindizr().is_err());
}
