use bindizr_core::{
    dns::{SoaInterval, Ttl},
    model::zone_version::{ChangeSource, ZoneVersionId},
};
use sqlx::sqlite::SqlitePoolOptions;

use super::*;

/// Build the real SQLite schema with a parent zone and an unwritten version.
async fn fixture() -> (Pool<Sqlite>, ZoneVersion) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    for query in crate::schema::sqlite::table_creation_queries() {
        sqlx::query(query).execute(&pool).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO zones (id, name, mname, rname, default_ttl, serial, created_at)
         VALUES (1, 'example.com', 'ns1.example.com', 'admin@example.com', 3600, 1, ?)",
    )
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();
    let version = ZoneVersion {
        id: ZoneVersionId::UNWRITTEN,
        zone_id: ZoneId::from(1),
        serial: Serial::from(1),
        mname: "ns1.example.com".into(),
        rname: "admin.example.com".into(),
        default_ttl: Ttl::from_secs(3600),
        refresh: SoaInterval::from_secs(300),
        retry: SoaInterval::from_secs(60),
        expire: SoaInterval::from_secs(3600000),
        minimum_ttl: Ttl::from_secs(86400),
        change_source: ChangeSource::Socket,
        changed_by: None,
        created_at: Utc::now(),
    };
    (pool, version)
}

/// Insert and replace both actor columns, including clearing a previous identity.
#[tokio::test]
async fn actor_columns_round_trip_through_upsert_and_reads() {
    let (pool, mut version) = fixture().await;
    for (source, actor, expected_kind, expected_name) in [
        (
            ChangeSource::Api,
            Some(ChangeActor::Token {
                name: "admin".into(),
            }),
            Some("token"),
            Some("admin"),
        ),
        (
            ChangeSource::Nsupdate,
            Some(ChangeActor::TsigKey {
                name: "updater".into(),
            }),
            Some("tsig_key"),
            Some("updater"),
        ),
        (ChangeSource::Socket, None, None, None),
    ] {
        version.change_source = source;
        version.changed_by = actor.clone();
        let mut tx = pool.begin().await.unwrap();
        let saved = upsert_tx(&mut tx, version.clone()).await.unwrap();
        assert_eq!(saved.change_source, source);
        assert_eq!(saved.changed_by, actor);
        tx.commit().await.unwrap();

        let columns: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT changed_by_kind, changed_by_name FROM zone_versions")
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
        assert_eq!(read.changed_by, actor);
    }
}

/// SQL rejects partial identities and unknown kinds before they can be persisted.
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
        let err = sqlx::query("UPDATE zone_versions SET changed_by_kind = ?, changed_by_name = ?")
            .bind(kind)
            .bind(name)
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            err.as_database_error().unwrap().is_check_violation(),
            "{err}"
        );
    }
}
