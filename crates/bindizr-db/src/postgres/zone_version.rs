use chrono::Utc;
use sqlx::{AssertSqlSafe, Pool, Postgres, Transaction};

/// Exclude signer-only serials; retain user changes, unjournaled serials, and the current serial.
/// Reuse `$1` (zone id) to keep the current-serial subquery uncorrelated.
const USER_CHANGES_FILTER: &str = r#"
              AND (
                  zone_versions.serial = (SELECT zones.serial FROM zones WHERE zones.id = $1)
                  OR EXISTS (
                      SELECT 1 FROM zone_journal
                      WHERE zone_journal.zone_id = zone_versions.zone_id
                        AND zone_journal.serial = zone_versions.serial
                        AND zone_journal.derived = FALSE
                  )
                  OR NOT EXISTS (
                      SELECT 1 FROM zone_journal
                      WHERE zone_journal.zone_id = zone_versions.zone_id
                        AND zone_journal.serial = zone_versions.serial
                  )
              )"#;

use bindizr_core::{dns::Serial, model::zone::ZoneId};

use crate::{
    LockLevel,
    error::DatabaseError,
    model::zone_version::{VersionScope, ZoneVersion},
};

/// Insert or update a zone version in the current transaction.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, Postgres>,
    version: ZoneVersion,
) -> Result<ZoneVersion, DatabaseError> {
    sqlx::query_as::<_, ZoneVersion>(
        r#"
        INSERT INTO zone_versions (zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (zone_id, serial)
        DO UPDATE SET
            mname = EXCLUDED.mname,
            rname = EXCLUDED.rname,
            default_ttl = EXCLUDED.default_ttl,
            refresh = EXCLUDED.refresh,
            retry = EXCLUDED.retry,
            expire = EXCLUDED.expire,
            minimum_ttl = EXCLUDED.minimum_ttl,
            change_source = EXCLUDED.change_source,
            changed_by = EXCLUDED.changed_by
        RETURNING id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
        "#,
    )
    .bind(version.zone_id)
    .bind(version.serial)
    .bind(&version.mname)
    .bind(&version.rname)
    .bind(version.default_ttl)
    .bind(version.refresh)
    .bind(version.retry)
    .bind(version.expire)
    .bind(version.minimum_ttl)
    .bind(version.change_source.as_str())
    .bind(&version.changed_by)
    .bind(Utc::now())
    .fetch_one(&mut **tx)
    .await
    .map_err(DatabaseError::from)
}

/// Find a zone version by zone ID and serial.
pub(crate) async fn get_by_serial(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
    serial: Serial,
) -> Result<Option<ZoneVersion>, DatabaseError> {
    sqlx::query_as::<_, ZoneVersion>(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
        FROM zone_versions
        WHERE zone_id = $1 AND serial = $2
        "#,
    )
    .bind(zone_id)
    .bind(serial)
    .fetch_optional(pool)
    .await
    .map_err(DatabaseError::from)
}

/// List zone versions in the closed interval `[from_serial, to_serial]`.
pub(crate) async fn list_in_serial_range(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<Vec<ZoneVersion>, DatabaseError> {
    sqlx::query_as::<_, ZoneVersion>(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
        FROM zone_versions
        WHERE zone_id = $1 AND serial >= $2 AND serial <= $3
        "#,
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_all(pool)
    .await
    .map_err(DatabaseError::from)
}

/// List zone versions for a zone.
pub(crate) async fn list_by_scope(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
    scope: VersionScope,
    limit: u32,
    offset: u64,
) -> Result<Vec<ZoneVersion>, DatabaseError> {
    let filter = match scope {
        VersionScope::UserChanges => USER_CHANGES_FILTER,
        VersionScope::All => "",
    };
    sqlx::query_as::<_, ZoneVersion>(AssertSqlSafe(format!(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
        FROM zone_versions
        WHERE zone_id = $1{filter}
        ORDER BY serial DESC
        LIMIT $2 OFFSET $3
        "#
    )))
    .bind(zone_id)
    .bind(i64::from(limit))
    .bind(i64::try_from(offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(DatabaseError::from)
}

/// Count zone versions using the requested change filter.
pub(crate) async fn count_by_scope(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
    scope: VersionScope,
) -> Result<u64, DatabaseError> {
    let filter = match scope {
        VersionScope::UserChanges => USER_CHANGES_FILTER,
        VersionScope::All => "",
    };
    let count: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM zone_versions WHERE zone_id = $1{filter}"
    )))
    .bind(zone_id)
    .fetch_one(pool)
    .await?;
    Ok(count as u64)
}

/// Find a zone version by zone ID and serial in the current transaction.
pub(crate) async fn get_by_serial_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    serial: Serial,
    lock_level: LockLevel,
) -> Result<Option<ZoneVersion>, DatabaseError> {
    sqlx::query_as::<_, ZoneVersion>(
        AssertSqlSafe(format!("{}{}", r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by, created_at
        FROM zone_versions
        WHERE zone_id = $1 AND serial = $2
        "#, lock_level.clause())),
    )
    .bind(zone_id)
    .bind(serial)
    .fetch_optional(&mut **tx)
    .await
    .map_err(DatabaseError::from)
}

/// Prune one zone's old versions, keeping its newest, in the current transaction.
pub(crate) async fn prune_by_zone_id_older_than_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<u64, DatabaseError> {
    // The zone's newest version survives regardless of age: the IXFR
    // up-to-date response reads it.
    let result = sqlx::query(
        r#"
        DELETE FROM zone_versions
        WHERE zone_id = $1 AND created_at < $2
          AND serial < (SELECT MAX(serial) FROM zone_versions WHERE zone_id = $1)
        "#,
    )
    .bind(zone_id)
    .bind(cutoff)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}
