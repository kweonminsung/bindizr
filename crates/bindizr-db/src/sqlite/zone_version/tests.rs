use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::{SoaInterval, Ttl};
use bindizr_core::model::change::ChangeSource;
use bindizr_core::model::zone_version::ZoneVersionId;
use sqlx::sqlite::SqlitePoolOptions;

use super::*;
use crate::schema::sqlite;
use crate::sqlite::{catalog_zone, zone_change};

/// Build the real SQLite schema with a parent zone and an unwritten version.
async fn fixture() -> (Pool<Sqlite>, ZoneVersion) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    for query in sqlite::table_creation_queries() {
        sqlx::query(query).execute(&pool).await.unwrap();
    }

    sqlx::query(
        "INSERT INTO zones (id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, created_at)
         VALUES (1, 'example.com', 'ns1.example.com', 'admin@example.com', 3600, 1, 300, 60, 3600000, 86400, ?)",
    )
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    let version = ZoneVersion {
        id: ZoneVersionId::UNWRITTEN,
        zone_id: ZoneId::from(1),
        serial: Serial::from(1),
        mname: "ns1.example.com".to_string(),
        rname: "admin.example.com".to_string(),
        default_ttl: Ttl::from_secs(3600),
        refresh: SoaInterval::from_secs(300),
        retry: SoaInterval::from_secs(60),
        expire: SoaInterval::from_secs(3_600_000),
        minimum_ttl: Ttl::from_secs(86400),
        change_source: ChangeSource::Socket,
        changed_by: None,
        created_at: Utc::now(),
    };

    (pool, version)
}

/// Verify that upserts insert and replace both actor columns, including
/// clearing a previous identity.
#[tokio::test]
async fn actor_columns_round_trip_through_upsert_and_reads() {
    let (pool, mut version) = fixture().await;

    for (source, actor, expected_kind, expected_name) in [
        (
            ChangeSource::Api,
            Some(ChangeActor::Token {
                name: "admin".to_string(),
            }),
            Some("token"),
            Some("admin"),
        ),
        (
            ChangeSource::Nsupdate,
            Some(ChangeActor::TsigKey {
                name: "updater".to_string(),
            }),
            Some("tsig_key"),
            Some("updater"),
        ),
        (ChangeSource::Socket, None, None, None),
    ] {
        version.change_source = source;
        version.changed_by = actor.clone();

        let mut tx = pool.begin().await.unwrap();
        upsert_tx(&mut tx, version.clone()).await.unwrap();
        tx.commit().await.unwrap();

        let columns = sqlx::query_as::<_, (Option<String>, Option<String>)>(
            "SELECT changed_by_kind, changed_by_name FROM zone_versions",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(columns.0.as_deref(), expected_kind);
        assert_eq!(columns.1.as_deref(), expected_name);

        let mut tx = pool.begin().await.unwrap();
        let read = get_by_serial_tx(
            &mut tx,
            version.zone_id,
            version.serial,
            LockLevel::Unlocked,
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();

        assert_eq!(read.change_source, source);
        assert_eq!(read.changed_by, actor);
    }
}

/// Verify that SQL rejects partial identities and unknown kinds before they
/// can be persisted.
#[tokio::test]
async fn actor_columns_reject_partial_or_unknown_identities() {
    let (pool, version) = fixture().await;
    let mut tx = pool.begin().await.unwrap();
    upsert_tx(&mut tx, version).await.unwrap();
    tx.commit().await.unwrap();

    for (kind, name) in [
        (Some("token"), None),
        (None, Some("admin")),
        (Some("unknown"), Some("admin")),
    ] {
        let error =
            sqlx::query("UPDATE zone_versions SET changed_by_kind = ?, changed_by_name = ?")
                .bind(kind)
                .bind(name)
                .execute(&pool)
                .await
                .unwrap_err();

        assert!(
            error.as_database_error().unwrap().is_check_violation(),
            "{error}"
        );
    }
}

/// Verify that cyclic queries span MAX to zero and that pruning retains only
/// unambiguous history.
#[tokio::test]
async fn history_ranges_wrap_and_prune_to_the_unambiguous_half_range() {
    let (pool, mut version) = fixture().await;
    let mut tx = pool.begin().await.unwrap();

    for serial in [u32::MAX - 1, u32::MAX, 0, 1, 0x8000_0001] {
        version.serial = Serial::from(serial);
        upsert_tx(&mut tx, version.clone()).await.unwrap();
        sqlx::query(
            "INSERT INTO zone_journal (zone_id, serial, operation, record_name, record_type, record_value, record_rdata, record_ttl, record_priority, derived, created_at) VALUES (1, ?, 'ADD', 'www', 'A', '192.0.2.1', NULL, 300, NULL, FALSE, ?)",
        )
        .bind(version.serial)
        .bind(Utc::now())
        .execute(&mut *tx)
        .await
        .unwrap();
    }

    let from = Serial::from(u32::MAX);
    let to = Serial::from(1);

    let mut versions: Vec<_> = list_in_serial_range_tx(&mut tx, version.zone_id, from, to)
        .await
        .unwrap()
        .into_iter()
        .map(|version| version.serial.as_u32())
        .collect();
    versions.sort_unstable();

    assert_eq!(versions, [0, 1, u32::MAX]);

    let journal = zone_change::list_between_serials_tx(
        &mut tx,
        version.zone_id,
        from,
        to,
        LockLevel::Unlocked,
    )
    .await
    .unwrap();

    assert_eq!(
        journal
            .iter()
            .map(|change| change.serial.as_u32())
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(
        prune_by_zone_id_outside_serial_window_tx(&mut tx, version.zone_id, to)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        zone_change::prune_by_zone_id_outside_serial_window_tx(&mut tx, version.zone_id, to)
            .await
            .unwrap(),
        1
    );
}

/// Verify that a changed catalog digest past the maximum serial wraps it to
/// one, never zero (RFC 2136, Section 7.11), and the same digest keeps it.
#[tokio::test]
async fn catalog_serial_wraps_to_one_when_the_digest_changes_past_max() {
    let (pool, _) = fixture().await;
    let mut tx = pool.begin().await.unwrap();
    let from = Serial::from(u32::MAX);
    let catalog_zone_name = ZoneName::parse("catalog.example").unwrap();

    assert_eq!(
        catalog_zone::upsert_tx(&mut tx, &catalog_zone_name, "one", from)
            .await
            .unwrap(),
        from
    );

    assert_eq!(
        catalog_zone::upsert_tx(&mut tx, &catalog_zone_name, "two", from)
            .await
            .unwrap(),
        Serial::from(1)
    );
    assert_eq!(
        catalog_zone::upsert_tx(&mut tx, &catalog_zone_name, "two", from)
            .await
            .unwrap(),
        Serial::from(1)
    );
}
