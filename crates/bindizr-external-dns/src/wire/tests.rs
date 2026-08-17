use serde_json::json;

use super::{
    BindizrRecordItem, BindizrRrset, Changes, DomainFilter, Endpoint, ProviderSpecificProperty,
    group_records_into_endpoints, merge_adjusted_endpoints, to_bindizr_changes, to_bindizr_rrsets,
    validate_endpoint,
};

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
fn changes_deserializes_plan_wire_format() {
    let parsed: Changes = serde_json::from_value(json!({
        "create": [{"dnsName": "a.example.com", "targets": ["192.0.2.1"], "recordType": "A"}],
        "updateOld": [{"dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A"}],
        "updateNew": [{"dnsName": "b.example.com", "targets": ["192.0.2.3"], "recordType": "A"}],
        "delete": [{"dnsName": "c.example.com", "targets": ["192.0.2.4"], "recordType": "A"}]
    }))
    .unwrap();

    assert_eq!(parsed.create.len(), 1);
    assert_eq!(parsed.update_old.len(), 1);
    assert_eq!(parsed.update_new.len(), 1);
    assert_eq!(parsed.delete.len(), 1);

    let empty: Changes = serde_json::from_value(json!({})).unwrap();
    assert!(empty.create.is_empty());
}

#[test]
fn domain_filter_serializes_include_list() {
    let filter = DomainFilter {
        include: vec!["example.com".to_string()],
    };
    assert_eq!(
        serde_json::to_value(&filter).unwrap(),
        json!({"include": ["example.com"]})
    );
    assert_eq!(
        serde_json::to_value(DomainFilter::default()).unwrap(),
        json!({})
    );
}

#[test]
fn validate_endpoint_rejects_unsupported_shapes() {
    assert!(validate_endpoint(&endpoint("", "A", 0, &["192.0.2.1"])).is_err());
    assert!(validate_endpoint(&endpoint("a.example.com", "NS", 0, &["x"])).is_err());
    assert!(validate_endpoint(&endpoint("a.example.com", "MX", 0, &["x"])).is_err());
    assert!(validate_endpoint(&endpoint("a.example.com", "A", 0, &[])).is_err());
    assert!(validate_endpoint(&endpoint("a.example.com", "A", 0, &[""])).is_err());
    assert!(validate_endpoint(&endpoint("a.example.com", "CNAME", 0, &["a.", "b."])).is_err());
    assert!(validate_endpoint(&endpoint("a.example.com", "A", -1, &["192.0.2.1"])).is_err());

    let mut with_set_id = endpoint("a.example.com", "A", 0, &["192.0.2.1"]);
    with_set_id.set_identifier = "weighted".to_string();
    assert!(validate_endpoint(&with_set_id).is_err());

    assert!(validate_endpoint(&endpoint("a.example.com", "a", 300, &["192.0.2.1"])).is_ok());

    // Whitespace-only content is valid TXT rdata but garbage for other types.
    assert!(validate_endpoint(&endpoint("a.example.com", "A", 0, &["   "])).is_err());
    assert!(validate_endpoint(&endpoint("t.example.com", "TXT", 0, &["   "])).is_ok());
}

#[test]
fn to_bindizr_changes_pairs_updates_and_maps_ttl() {
    let changes: Changes = serde_json::from_value(json!({
        "create": [{"dnsName": "a.example.com", "targets": ["192.0.2.1"], "recordType": "A", "recordTTL": 300}],
        "updateOld": [{"dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A"}],
        "updateNew": [{"dnsName": "b.example.com", "targets": ["192.0.2.3"], "recordType": "A"}]
    }))
    .unwrap();

    let bindizr = to_bindizr_changes(&changes).unwrap();

    assert_eq!(bindizr.creates.len(), 1);
    assert_eq!(bindizr.creates[0].ttl, Some(300));
    assert_eq!(bindizr.updates.len(), 1);
    // TTL 0 (unset) maps to None so the server applies the zone TTL.
    assert_eq!(bindizr.updates[0].old.ttl, None);
    assert_eq!(bindizr.updates[0].new.values, vec!["192.0.2.3"]);
    assert!(bindizr.deletes.is_empty());
}

#[test]
fn to_bindizr_changes_rejects_mismatched_update_pairs() {
    let changes: Changes = serde_json::from_value(json!({
        "updateOld": [{"dnsName": "b.example.com", "targets": ["192.0.2.2"], "recordType": "A"}],
        "updateNew": []
    }))
    .unwrap();

    assert!(to_bindizr_changes(&changes).is_err());
}

#[test]
fn group_records_builds_one_endpoint_per_rrset() {
    let records = vec![
        BindizrRecordItem {
            name: "app.example.com".to_string(),
            record_type: "A".to_string(),
            ttl: 300,
            value: "192.0.2.2".to_string(),
        },
        BindizrRecordItem {
            name: "app.example.com".to_string(),
            record_type: "A".to_string(),
            ttl: 300,
            value: "192.0.2.1".to_string(),
        },
        BindizrRecordItem {
            name: "app.example.com".to_string(),
            record_type: "TXT".to_string(),
            ttl: 3600,
            value: "\"heritage=external-dns,external-dns/owner=default\"".to_string(),
        },
    ];

    let endpoints = group_records_into_endpoints(records);

    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].record_type, "A");
    assert_eq!(endpoints[0].targets, vec!["192.0.2.1", "192.0.2.2"]);
    assert_eq!(endpoints[0].record_ttl, 300);
    assert_eq!(endpoints[1].record_type, "TXT");
    assert_eq!(
        endpoints[1].targets,
        vec!["\"heritage=external-dns,external-dns/owner=default\""]
    );
}

#[test]
fn to_bindizr_rrsets_validates_and_converts_for_adjust() {
    let rrsets = to_bindizr_rrsets(&[
        endpoint("a.example.com", "a", 300, &["192.0.2.1"]),
        endpoint("t.example.com", "TXT", 0, &["v=spf1 -all"]),
    ])
    .unwrap();

    assert_eq!(rrsets[0].record_type, "A");
    assert_eq!(rrsets[0].ttl, Some(300));
    assert_eq!(rrsets[1].ttl, None);
    assert_eq!(rrsets[1].values, vec!["v=spf1 -all"]);

    // One invalid endpoint rejects the whole set before any round trip.
    assert!(
        to_bindizr_rrsets(&[
            endpoint("a.example.com", "A", 300, &["192.0.2.1"]),
            endpoint("b.example.com", "SRV", 0, &["x"]),
        ])
        .is_err()
    );
}

#[test]
fn merge_adjusted_endpoints_keeps_identity_and_takes_canonical_fields() {
    let mut desired = endpoint("a.example.com", "aaaa", 300, &["2001:0DB8::1"]);
    desired.labels.insert("owner".into(), "default".into());
    desired.provider_specific = vec![ProviderSpecificProperty {
        name: "webhook/flag".to_string(),
        value: "on".to_string(),
    }];

    let merged = merge_adjusted_endpoints(
        vec![desired],
        vec![BindizrRrset {
            name: "a.example.com".to_string(),
            record_type: "AAAA".to_string(),
            ttl: Some(300),
            values: vec!["2001:db8::1".to_string()],
        }],
    );

    assert_eq!(merged[0].dns_name, "a.example.com");
    assert_eq!(
        merged[0].labels.get("owner").map(String::as_str),
        Some("default")
    );
    assert!(merged[0].provider_specific.is_empty());
    assert_eq!(merged[0].record_type, "AAAA");
    assert_eq!(merged[0].record_ttl, 300);
    assert_eq!(merged[0].targets, vec!["2001:db8::1"]);
}
