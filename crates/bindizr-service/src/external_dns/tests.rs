use bindizr_core::dns::name::{OwnerName, ZoneName};
use chrono::Utc;

use super::{
    change_set::{ZoneOps, adjust_rrset, group_ops_by_zone, parse_changes_request, parse_rrset_op},
    policy::{authoritative_zone, normalize_lookup_name},
};
use crate::{
    authorization::Caller,
    error::ErrorCode,
    model::{
        record::{Record, RecordType},
        token_grant::TokenGrant,
        zone::Zone,
    },
    types::{ExternalDnsChangesRequest, ExternalDnsRecord, ExternalDnsRecordUpdate},
};

/// Build a zone fixture for the test.
fn test_zone(id: i32, name: &str) -> Zone {
    Zone {
        id,
        name: ZoneName::from_row(name),
        mname: format!("ns1.{}", name),
        rname: format!("hostmaster@{}", name),
        default_ttl: 3600,
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 604800,
        minimum_ttl: 86400,
        dnssec_policy_id: None,
        parent_ns_addrs: None,
        enabled: true,
        description: None,
        created_at: Utc::now(),
    }
}

/// Build a record fixture with the requested fields.
fn test_record(id: i32, name: &str, record_type: RecordType, value: &str, ttl: i32) -> Record {
    Record {
        id,
        name: OwnerName::from_row(name),
        record_type,
        value: value.to_string(),
        ttl,
        priority: None,
        zone_id: 1,
        created_at: Utc::now(),
    }
}

/// Build a record-group fixture from the supplied values.
fn rrset(name: &str, record_type: &str, ttl: Option<i32>, values: &[&str]) -> ExternalDnsRecord {
    ExternalDnsRecord {
        name: name.to_string(),
        record_type: record_type.to_string(),
        ttl,
        values: values.iter().map(|v| v.to_string()).collect(),
    }
}

/// Verify that find authoritative zone picks most specific match.
#[test]
fn authoritative_zone_picks_most_specific_match() {
    let zones = vec![
        test_zone(1, "example.com"),
        test_zone(2, "internal.example.com"),
    ];

    assert_eq!(
        authoritative_zone(&zones, "api.internal.example.com").map(|z| z.id),
        Some(2)
    );
    assert_eq!(
        authoritative_zone(&zones, "www.example.com").map(|z| z.id),
        Some(1)
    );
    assert_eq!(
        authoritative_zone(&zones, "internal.example.com").map(|z| z.id),
        Some(2)
    );
}

/// Verify that `authoritative_zone` requires label boundary.
#[test]
fn authoritative_zone_requires_label_boundary() {
    let zones = vec![test_zone(1, "example.com")];

    assert!(authoritative_zone(&zones, "notexample.com").is_none());
    assert!(authoritative_zone(&zones, "example.org").is_none());
}

/// Verify that an escaped dot does not put a name inside the zone it spells.
#[test]
fn an_escaped_dot_does_not_put_a_name_inside_the_zone_it_spells() {
    // `evil\.example.com` is the two labels [evil.example, com], so no zone
    // named example.com is authoritative for it.
    let zones = vec![test_zone(1, "example.com")];
    let name = normalize_lookup_name(r"evil\.example.com").unwrap();

    assert_eq!(name, r"evil\046example.com");
    assert!(authoritative_zone(&zones, &name).is_none());
}

/// Verify that `normalize_lookup_name` lowercases and strips trailing dot.
#[test]
fn normalize_lookup_name_lowercases_and_strips_trailing_dot() {
    assert_eq!(
        normalize_lookup_name("App.Example.COM.").unwrap(),
        "app.example.com"
    );
    assert!(normalize_lookup_name("").is_err());
    assert!(normalize_lookup_name("bad name.example.com").is_err());
}

/// Verify that `parse_rrset_op` rejects unsupported types.
#[test]
fn parse_rrset_op_rejects_unsupported_types() {
    for record_type in ["NS", "MX", "SRV", "SOA", "PTR"] {
        let err = parse_rrset_op(&rrset("a.example.com", record_type, None, &["x"])).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
    assert!(parse_rrset_op(&rrset("a.example.com", "BOGUS", None, &["x"])).is_err());
}

/// Verify that `parse_rrset_op` rejects multi value CNAME and empty values.
#[test]
fn parse_rrset_op_rejects_multi_value_cname_and_empty_values() {
    let err = parse_rrset_op(&rrset(
        "a.example.com",
        "CNAME",
        None,
        &["one.example.com", "two.example.com"],
    ))
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidRecordValue);

    let err = parse_rrset_op(&rrset("a.example.com", "A", None, &[])).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidInput);
}

/// Verify that `parse_rrset_op` normalizes TTL.
#[test]
fn parse_rrset_op_normalizes_ttl() {
    assert_eq!(
        parse_rrset_op(&rrset("a.example.com", "A", Some(0), &["192.0.2.1"]))
            .unwrap()
            .ttl,
        None
    );
    assert_eq!(
        parse_rrset_op(&rrset("a.example.com", "A", Some(300), &["192.0.2.1"]))
            .unwrap()
            .ttl,
        Some(300)
    );
    assert!(parse_rrset_op(&rrset("a.example.com", "A", Some(-1), &["192.0.2.1"])).is_err());
}

/// Verify that `parse_rrset_op` deduplicates equivalent ipv6 spellings.
#[test]
fn parse_rrset_op_deduplicates_equivalent_ipv6_spellings() {
    let op = parse_rrset_op(&rrset(
        "a.example.com",
        "AAAA",
        None,
        &["2001:DB8::1", "2001:db8:0:0:0:0:0:1"],
    ))
    .unwrap();

    assert_eq!(op.values, vec!["2001:db8::1".to_string()]);
}

/// Verify that parse RRSET op parses quoted TXT values.
#[test]
fn parse_rrset_op_parses_quoted_txt_values() {
    let op = parse_rrset_op(&rrset(
        "a.example.com",
        "TXT",
        None,
        &["\"heritage=external-dns,external-dns/owner=default\""],
    ))
    .unwrap();

    assert_eq!(op.record_type, RecordType::TXT);
    assert_eq!(
        op.values[0],
        "\"heritage=external-dns,external-dns/owner=default\""
    );
    assert!(parse_rrset_op(&rrset("a.example.com", "TXT", None, &["\"unterminated"])).is_err());
}

/// Verify that `adjust_rrset` canonicalizes type and values.
#[test]
fn adjust_rrset_canonicalizes_type_and_values() {
    let adjusted = adjust_rrset(&rrset(
        "v6.example.com",
        "aaaa",
        None,
        &["2001:0DB8::2", "2001:db8::1", "2001:db8:0:0:0:0:0:1"],
    ))
    .unwrap();

    assert_eq!(adjusted.record_type, "AAAA");
    assert_eq!(adjusted.values, vec!["2001:db8::1", "2001:db8::2"]);

    let adjusted = adjust_rrset(&rrset(
        "c.example.com",
        "CNAME",
        Some(300),
        &["CDN.Example.NET"],
    ))
    .unwrap();
    assert_eq!(adjusted.values, vec!["cdn.example.net."]);
    assert_eq!(adjusted.ttl, Some(300));
}

/// Verify that `adjust_rrset` returns TXT values in presentation form.
#[test]
fn adjust_rrset_returns_txt_values_in_presentation_form() {
    let adjusted = adjust_rrset(&rrset("t.example.com", "TXT", Some(0), &["v=spf1 -all"])).unwrap();
    assert_eq!(adjusted.values, vec!["\"v=spf1 -all\""]);
    // ExternalDNS sends TTL 0 for "not configured".
    assert_eq!(adjusted.ttl, None);

    // Already-canonical ownership records pass through byte-identical.
    let canonical = "\"heritage=external-dns,external-dns/owner=default\"";
    let adjusted = adjust_rrset(&rrset("t.example.com", "TXT", None, &[canonical])).unwrap();
    assert_eq!(adjusted.values, vec![canonical]);

    let adjusted = adjust_rrset(&rrset("t.example.com", "TXT", None, &["   "])).unwrap();
    assert_eq!(adjusted.values, vec![r#""   ""#]);
}

/// Verify that `adjust_rrset` passes unparseable values through.
#[test]
fn adjust_rrset_passes_unparseable_values_through() {
    let adjusted = adjust_rrset(&rrset("bad.example.com", "A", None, &["not-an-ip"])).unwrap();
    assert_eq!(adjusted.values, vec!["not-an-ip"]);
}

/// Verify that `adjust_rrset` rejects unsupported shapes.
#[test]
fn adjust_rrset_rejects_unsupported_shapes() {
    assert!(adjust_rrset(&rrset("a.example.com", "MX", None, &["x"])).is_err());
    assert!(adjust_rrset(&rrset("a.example.com", "A", Some(-1), &["192.0.2.1"])).is_err());
    assert!(adjust_rrset(&rrset("a.example.com", "A", None, &[])).is_err());
    assert!(adjust_rrset(&rrset("a.example.com", "CNAME", None, &["a.", "b."])).is_err());
}

/// Verify that group ops resolves subzone without parent fallback.
#[test]
fn group_ops_resolves_subzone_without_parent_fallback() {
    let zones = vec![
        test_zone(1, "example.com"),
        test_zone(2, "internal.example.com"),
    ];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("api.internal.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };
    let ops = parse_changes_request(&request).unwrap();

    let grouped = group_ops_by_zone(&Caller::Global, &zones, ops).unwrap();
    assert_eq!(grouped.len(), 1);
    assert!(grouped.contains_key(&ZoneName::from_row("internal.example.com")));
    assert_eq!(
        grouped[&ZoneName::from_row("internal.example.com")].adds[0].name,
        OwnerName::from_row("api")
    );
}

/// Verify that group ops rejects names without authoritative zone.
#[test]
fn group_ops_rejects_names_without_authoritative_zone() {
    let zones = vec![test_zone(1, "example.com")];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("app.other.org", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };
    let ops = parse_changes_request(&request).unwrap();

    let err = group_ops_by_zone(&Caller::Global, &zones, ops).unwrap_err();
    assert_eq!(err.code, ErrorCode::ZoneNotFound);
}

/// Verify that group ops reads a hidden zone as absent instead of its granted parent.
#[test]
fn group_ops_reads_a_hidden_zone_as_absent_instead_of_its_granted_parent() {
    let zones = vec![
        test_zone(1, "example.com"),
        test_zone(2, "internal.example.com"),
    ];
    let caller = Caller::Token {
        id: 7,
        name: "scoped".into(),
        grants: vec![TokenGrant {
            id: 1,
            zone_id: 1,
            api_token_id: 7,
            record_name_pattern: "*".to_string(),
            record_types: "*".to_string(),
            can_write: true,
            created_at: Utc::now(),
        }]
        .into(),
    };
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("api.internal.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };
    let ops = parse_changes_request(&request).unwrap();

    let err = group_ops_by_zone(&caller, &zones, ops).unwrap_err();
    assert_eq!(err.code, ErrorCode::ZoneNotFound);
    assert!(
        err.to_string()
            .contains("No zone is authoritative for 'api.internal.example.com'"),
        "{err}"
    );
}

/// Resolve an external-dns change request into operations for the test zone.
fn zone_ops(request: &ExternalDnsChangesRequest, zone: &Zone) -> ZoneOps {
    let ops = parse_changes_request(request).unwrap();
    let grouped = group_ops_by_zone(&Caller::Global, std::slice::from_ref(zone), ops).unwrap();
    grouped.into_values().next().unwrap_or_default()
}

/// Verify that change set creates new records with zone default TTL.
#[test]
fn change_set_creates_new_records_with_zone_default_ttl() {
    let zone = test_zone(1, "example.com");
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("app.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &[])
        .unwrap();

    assert!(change_set.deletes.is_empty());
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].name, OwnerName::from_row("app"));
    assert_eq!(change_set.creates[0].ttl, zone.default_ttl);
}

/// Verify that change set skips creates that already exist.
#[test]
fn change_set_skips_creates_that_already_exist() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("app.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

/// Verify that an existing value with a different TTL makes a create a no-op, avoiding
/// conflicts on every retry.
#[test]
fn change_set_skips_creates_whose_row_differs_only_in_ttl() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 300)];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset("app.example.com", "A", None, &["192.0.2.1"])],
        updates: vec![],
        deletes: vec![],
    };

    // No TTL on the RRset, so it resolves to the zone's 3600 — not the row's 300.
    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

/// Verify that an explicit TTL-only update replaces the stored row instead of cancelling itself
/// as unchanged.
#[test]
fn change_set_replaces_rows_when_an_update_moves_only_the_ttl() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 300)];
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![ExternalDnsRecordUpdate {
            old: rrset("app.example.com", "A", Some(300), &["192.0.2.1"]),
            new: rrset("app.example.com", "A", Some(900), &["192.0.2.1"]),
        }],
        deletes: vec![],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap();

    assert_eq!(change_set.deletes.len(), 1);
    assert_eq!(change_set.deletes[0].id, 10);
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].ttl, 900);
}

/// Verify that change set skips deletes of absent records.
#[test]
fn change_set_skips_deletes_of_absent_records() {
    let zone = test_zone(1, "example.com");
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![],
        deletes: vec![rrset("gone.example.com", "A", None, &["192.0.2.9"])],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &[])
        .unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

/// Verify that change set cancels unchanged updates even with reordered targets.
#[test]
fn change_set_cancels_unchanged_updates_even_with_reordered_targets() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![ExternalDnsRecordUpdate {
            old: rrset("app.example.com", "A", None, &["192.0.2.1", "192.0.2.2"]),
            new: rrset("app.example.com", "A", None, &["192.0.2.2", "192.0.2.1"]),
        }],
        deletes: vec![],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap();

    assert!(change_set.deletes.is_empty());
    assert!(change_set.creates.is_empty());
}

/// Verify that change set replaces rows when update changes targets.
#[test]
fn change_set_replaces_rows_when_update_changes_targets() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![ExternalDnsRecordUpdate {
            old: rrset("app.example.com", "A", None, &["192.0.2.1", "192.0.2.2"]),
            new: rrset("app.example.com", "A", None, &["192.0.2.1", "192.0.2.3"]),
        }],
        deletes: vec![],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap();

    assert_eq!(
        change_set.deletes.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![11]
    );
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].value, "192.0.2.3");
}

/// Verify that change set replaces whole RRSET when TTL changes.
#[test]
fn change_set_replaces_whole_rrset_when_ttl_changes() {
    let zone = test_zone(1, "example.com");
    let existing = vec![
        test_record(10, "app", RecordType::A, "192.0.2.1", 3600),
        test_record(11, "app", RecordType::A, "192.0.2.2", 3600),
    ];
    let request = ExternalDnsChangesRequest {
        creates: vec![],
        updates: vec![ExternalDnsRecordUpdate {
            old: rrset(
                "app.example.com",
                "A",
                Some(3600),
                &["192.0.2.1", "192.0.2.2"],
            ),
            new: rrset(
                "app.example.com",
                "A",
                Some(300),
                &["192.0.2.1", "192.0.2.2"],
            ),
        }],
        deletes: vec![],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap();

    assert_eq!(change_set.deletes.len(), 2);
    assert_eq!(change_set.creates.len(), 2);
    assert!(change_set.creates.iter().all(|record| record.ttl == 300));
}

/// Verify that change set enforces CNAME exclusivity.
#[test]
fn change_set_enforces_cname_exclusivity() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset(
            "app.example.com",
            "CNAME",
            None,
            &["cdn.example.net"],
        )],
        updates: vec![],
        deletes: vec![],
    };

    let err = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::RecordConflict);
}

/// Verify that change set allows CNAME when conflicting row is deleted in same request.
#[test]
fn change_set_allows_cname_when_conflicting_row_is_deleted_in_same_request() {
    let zone = test_zone(1, "example.com");
    let existing = vec![test_record(10, "app", RecordType::A, "192.0.2.1", 3600)];
    let request = ExternalDnsChangesRequest {
        creates: vec![rrset(
            "app.example.com",
            "CNAME",
            None,
            &["cdn.example.net"],
        )],
        updates: vec![],
        deletes: vec![rrset("app.example.com", "A", None, &["192.0.2.1"])],
    };

    let change_set = zone_ops(&request, &zone)
        .compute_change_set(&zone, &existing)
        .unwrap();

    assert_eq!(change_set.deletes.len(), 1);
    assert_eq!(change_set.creates.len(), 1);
    assert_eq!(change_set.creates[0].record_type, RecordType::CNAME);
}
