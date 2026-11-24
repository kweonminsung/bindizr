use std::time::{Duration, Instant};

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use super::*;
use crate::schema;

/// Verify that the stamp gives up rather than wait while another
/// connection holds the database writer, stamps once it is free, and leaves
/// no pooled connection without its busy timeout.
#[tokio::test]
async fn update_last_used_at_skips_a_held_writer() {
    let directory = tempfile::tempdir().unwrap();
    let options = SqliteConnectOptions::new()
        .filename(directory.path().join("stamp.sqlite"))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query(sqlite::BUSY_TIMEOUT_PRAGMA)
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .unwrap();

    for query in schema::sqlite::table_creation_queries() {
        sqlx::query(query).execute(&pool).await.unwrap();
    }

    sqlx::query("INSERT INTO roles (id, name, created_at) VALUES (1, 'r', ?)")
        .bind(Utc::now())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO api_tokens (id, name, token_hash, role_id, created_at) VALUES (1, 't', 'h', 1, ?)",
    )
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    let mut writer = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let started = Instant::now();

    assert!(
        !update_last_used_at(&pool, ApiTokenId::from(1), Utc::now())
            .await
            .unwrap()
    );
    assert!(started.elapsed() < Duration::from_secs(5));

    sqlx::query("SELECT 1").execute(&mut *writer).await.unwrap();
    writer.rollback().await.unwrap();

    assert!(
        update_last_used_at(&pool, ApiTokenId::from(1), Utc::now())
            .await
            .unwrap()
    );

    // Every pooled connection keeps the wait, the stamp's own included.
    for _ in 0..2 {
        let timeout = sqlx::query_scalar::<_, i64>("PRAGMA busy_timeout")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(timeout, 15000);
    }
}

/// Verify that a stamp on the only connection of an in-memory database
/// returns it to the pool rather than discard the database.
#[tokio::test]
async fn update_last_used_at_keeps_an_in_memory_database() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    for query in schema::sqlite::table_creation_queries() {
        sqlx::query(query).execute(&pool).await.unwrap();
    }

    assert!(
        !update_last_used_at(&pool, ApiTokenId::from(1), Utc::now())
            .await
            .unwrap()
    );
    assert_eq!(count_all(&pool).await.unwrap(), 0);
}
