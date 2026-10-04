//! The listing SQL repeats `RoleGrants`' rules for paging; these tests hold
//! the two to the same answers. Every backend shares the match fragment.

use std::collections::BTreeSet;

use bindizr_core::{
    dns::name::{OwnerName, ZoneName},
    model::{
        record::RecordType,
        role::RoleId,
        role_grant::{Action, RoleGrant, RoleGrantId, RoleGrants, RoleZoneScope},
        zone::ZoneId,
    },
};
use chrono::Utc;
use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};

use crate::{dnssec_record::DnssecRecordFilter, record::RecordFilter, zone::ZoneFilter};

/// Owner names text matching gets wrong: `evil\.sub` is one label (RFC 1035,
/// Section 5.1), and `xsub` shares a suffix with `sub` but not a label.
const NAMES: [&str; 9] = [
    "@",
    "www",
    "sub",
    "a.sub",
    "b.a.sub",
    "xsub",
    "evil\\.sub",
    "*.wild",
    "dyn",
];

const TYPES: [RecordType; 2] = [RecordType::A, RecordType::Txt];

/// Two zones with a record of each type at every name, and an RRSIG per name.
async fn fixture() -> Pool<Sqlite> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    for query in crate::schema::sqlite::table_creation_queries() {
        sqlx::query(query).execute(&pool).await.unwrap();
    }
    for (id, zone) in [(1, "example.com"), (2, "other.com")] {
        sqlx::query(
            "INSERT INTO zones (id, name, mname, rname, default_ttl, serial, created_at)
             VALUES (?, ?, 'ns1.example.com', 'admin@example.com', 3600, 1, ?)",
        )
        .bind(id)
        .bind(zone)
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
        let zone_name = ZoneName::parse(zone).unwrap();
        for name in NAMES {
            let owner = OwnerName::parse_in_zone(name, &zone_name).unwrap();
            for record_type in TYPES {
                sqlx::query(
                    "INSERT INTO records (name, record_type, value, display_value, ttl, created_at, zone_id)
                     VALUES (?, ?, 'v', 'v', 300, ?, ?)",
                )
                .bind(&owner)
                .bind(record_type.as_str())
                .bind(Utc::now())
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
            }
            if id == 1 {
                sqlx::query(
                    "INSERT INTO dnssec_records (zone_id, name, record_type, covered_record_type, ttl, rdata)
                     VALUES (1, ?, 46, 1, 300, X'00')",
                )
                .bind(&owner)
                .execute(&pool)
                .await
                .unwrap();
            }
        }
    }
    pool
}

/// A grant of `actions` in `zone` (all zones when `None`).
fn grant(zone: Option<i32>, actions: &[Action], pattern: &str, types: &str) -> RoleGrant {
    RoleGrant {
        id: RoleGrantId::UNWRITTEN,
        role_id: RoleId::UNWRITTEN,
        zone_scope: RoleZoneScope::from(zone.map(ZoneId::from)),
        actions: actions.iter().copied().collect(),
        record_name_pattern: pattern.to_string(),
        record_types: types.to_string(),
        created_at: Utc::now(),
    }
}

/// Write a role holding `grants` and return its id.
async fn create_role(pool: &Pool<Sqlite>, index: usize, grants: &[RoleGrant]) -> RoleId {
    let role_id: i32 =
        sqlx::query_scalar("INSERT INTO roles (name, created_at) VALUES (?, ?) RETURNING id")
            .bind(format!("role{index}"))
            .bind(Utc::now())
            .fetch_one(pool)
            .await
            .unwrap();
    for grant in grants {
        sqlx::query(
            "INSERT INTO role_grants (role_id, zone_id, actions, record_name_pattern, record_types, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(role_id)
        .bind(grant.zone_scope.zone_id())
        .bind(grant.actions.to_string())
        .bind(&grant.record_name_pattern)
        .bind(&grant.record_types)
        .bind(Utc::now())
        .execute(pool)
        .await
        .unwrap();
    }
    RoleId::from(role_id)
}

/// Roles covering each pattern shape, type lists, a union, and no read.
fn roles() -> Vec<Vec<RoleGrant>> {
    let read = &[Action::RecordRead][..];
    vec![
        vec![grant(None, read, "*", "*")],
        vec![grant(Some(1), read, "@", "*")],
        vec![grant(Some(1), read, "sub", "*")],
        vec![grant(Some(1), read, "*.sub", "*")],
        vec![grant(Some(1), read, "*.sub", "A")],
        vec![grant(Some(1), read, "evil\\046sub", "*")],
        vec![grant(Some(1), read, "*.wild", "TXT")],
        vec![
            grant(Some(1), read, "www", "A"),
            grant(Some(2), read, "*.sub", "*"),
        ],
        vec![grant(
            None,
            &[Action::RecordCreate, Action::ZoneRead],
            "*",
            "*",
        )],
    ]
}

/// Verify that the record, DNSSEC record, and zone listings narrow each role
/// exactly as `RoleGrants` answers row by row.
#[tokio::test]
async fn listings_narrow_each_role_as_role_grants_answer() {
    let pool = fixture().await;
    let all_records = super::record::list_by_filter_with_zone(&pool, RecordFilter::default())
        .await
        .unwrap();
    let all_dnssec =
        super::dnssec_record::list_by_filter_with_zone(&pool, DnssecRecordFilter::default())
            .await
            .unwrap();
    let all_zones = super::zone::list_by_filter(&pool, ZoneFilter::default())
        .await
        .unwrap();
    assert_eq!(all_records.len(), 2 * NAMES.len() * TYPES.len());
    assert_eq!(all_dnssec.len(), NAMES.len());

    for (index, grants) in roles().into_iter().enumerate() {
        let role_id = create_role(&pool, index, &grants).await;
        let rules = RoleGrants::from(grants.clone());
        let case = format!("role {index}: {grants:?}");

        let listed: BTreeSet<_> = super::record::list_by_filter_with_zone(
            &pool,
            RecordFilter {
                scope_role_id: Some(role_id),
                ..RecordFilter::default()
            },
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.zone_id, row.name.to_string(), row.record_type))
        .collect();
        let expected: BTreeSet<_> = all_records
            .iter()
            .filter(|row| {
                rules.covers_record(
                    Action::RecordRead,
                    row.zone_id,
                    &row.name,
                    Some(&row.record_type),
                )
            })
            .map(|row| (row.zone_id, row.name.to_string(), row.record_type))
            .collect();
        assert_eq!(listed, expected, "records, {case}");
        // Equal empty sets would prove nothing, so a reading role must reach rows.
        let reads = grants
            .iter()
            .any(|grant| grant.actions.contains(Action::RecordRead));
        assert_eq!(!expected.is_empty(), reads, "records reached, {case}");

        // A derived row carries no type of the grant's vocabulary.
        let listed: BTreeSet<_> = super::dnssec_record::list_by_filter_with_zone(
            &pool,
            DnssecRecordFilter {
                scope_role_id: Some(role_id),
                ..DnssecRecordFilter::default()
            },
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.name.to_string())
        .collect();
        let expected: BTreeSet<_> = all_dnssec
            .iter()
            .filter(|row| rules.covers_record(Action::RecordRead, row.zone_id, &row.name, None))
            .map(|row| row.name.to_string())
            .collect();
        assert_eq!(listed, expected, "DNSSEC records, {case}");

        let listed: BTreeSet<_> = super::zone::list_by_filter(
            &pool,
            ZoneFilter {
                scope_role_id: Some(role_id),
                ..ZoneFilter::default()
            },
        )
        .await
        .unwrap()
        .into_iter()
        .map(|zone| zone.id)
        .collect();
        let expected: BTreeSet<_> = all_zones
            .iter()
            .filter(|zone| rules.reaches_zone(zone.id))
            .map(|zone| zone.id)
            .collect();
        assert_eq!(listed, expected, "zones, {case}");
    }
}
