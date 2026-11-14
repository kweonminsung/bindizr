use bindizr_core::dns::Serial;
use bindizr_core::model::change::ChangeActor;
use bindizr_core::model::zone::ZoneId;
use bindizr_core::model::zone_version::{VersionFilter, ZoneVersion};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres, Transaction};

use crate::LockLevel;
use crate::error::DatabaseError;

/// Exclude past versions whose nonempty journal contains only derived changes.
/// Reuse `$1` (zone id) to keep the current-serial subquery uncorrelated.
const EXCLUDE_PAST_SIGNER_ONLY_FILTER: &str = r#"
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

/// Insert or update a zone version in the current transaction.
pub(crate) async fn upsert_tx(
    tx: &mut Transaction<'_, Postgres>,
    version: ZoneVersion,
) -> Result<ZoneVersion, DatabaseError> {
    let (changed_by_kind, changed_by_name) = version
        .changed_by
        .as_ref()
        .map(ChangeActor::as_columns)
        .unzip();

    let version = sqlx::query_as::<_, ZoneVersion>(
        r#"
        INSERT INTO zone_versions (zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
            changed_by_kind = EXCLUDED.changed_by_kind,
            changed_by_name = EXCLUDED.changed_by_name
        RETURNING id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at
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
    .bind(changed_by_kind)
    .bind(changed_by_name)
    .bind(Utc::now())
    .fetch_one(&mut **tx)
    .await?;

    Ok(version)
}

/// List the versions with serial in the closed interval `[from_serial,
/// to_serial]`; an IXFR needs both endpoint SOAs, unlike the journal's
/// half-open range.
pub(crate) async fn list_in_serial_range_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<Vec<ZoneVersion>, DatabaseError> {
    let versions = sqlx::query_as::<_, ZoneVersion>(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at
        FROM zone_versions
        WHERE zone_id = $1 AND ((serial >= $2 AND serial <= $3) OR ($2 > $3 AND (serial >= $2 OR serial <= $3)))
        "#,
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_all(&mut **tx)
    .await?;

    Ok(versions)
}

/// List the versions of a zone that `filter` covers, newest version first,
/// paginated; the current serial is always listed.
pub(crate) async fn list_by_filter(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
    filter: VersionFilter,
    limit: Option<u32>,
    offset: Option<u64>,
) -> Result<Vec<ZoneVersion>, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let predicate = match filter {
        VersionFilter::ExcludePastSignerOnly => EXCLUDE_PAST_SIGNER_ONLY_FILTER,
        VersionFilter::All => "",
    };
    let versions = sqlx::query_as::<_, ZoneVersion>(AssertSqlSafe(format!(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at
        FROM zone_versions
        WHERE zone_id = $1{predicate}
        ORDER BY created_at DESC, id DESC
        LIMIT $2 OFFSET $3
        "#
    )))
    .bind(zone_id)
    .bind(limit.map_or(i64::MAX, i64::from))
    .bind(offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
    .fetch_all(&mut *connection)
    .await?;

    Ok(versions)
}

/// Count the versions of a zone that `filter` covers.
pub(crate) async fn count_by_filter(
    pool: &Pool<Postgres>,
    zone_id: ZoneId,
    filter: VersionFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let predicate = match filter {
        VersionFilter::ExcludePastSignerOnly => EXCLUDE_PAST_SIGNER_ONLY_FILTER,
        VersionFilter::All => "",
    };
    let count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM zone_versions WHERE zone_id = $1{predicate}"
    )))
    .bind(zone_id)
    .fetch_one(&mut *connection)
    .await?;

    Ok(count as u64)
}

/// Get a zone version by serial consistently with mutations in the current
/// transaction.
pub(crate) async fn get_by_serial_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    serial: Serial,
    lock_level: LockLevel,
) -> Result<Option<ZoneVersion>, DatabaseError> {
    let version = sqlx::query_as::<_, ZoneVersion>(AssertSqlSafe(format!(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at
        FROM zone_versions
        WHERE zone_id = $1 AND serial = $2{}
        "#,
        lock_level.clause(),
    )))
    .bind(zone_id)
    .bind(serial)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(version)
}

/// Prune one zone's versions older than `cutoff`, always keeping its newest
/// (the IXFR up-to-date response reads it). Returns rows deleted.
pub(crate) async fn prune_by_zone_id_older_than_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    // Retain the newest version for up-to-date IXFR responses.
    let result = sqlx::query(
        r#"
        DELETE FROM zone_versions
        WHERE zone_id = $1 AND created_at < $2
          AND serial != (SELECT serial FROM zones WHERE id = $1)
        "#,
    )
    .bind(zone_id)
    .bind(cutoff)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}

/// Prune history outside the unambiguous RFC 1982 half-range behind the current serial.
pub(crate) async fn prune_by_zone_id_outside_serial_window_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    current: Serial,
) -> Result<u64, DatabaseError> {
    let result = sqlx::query(
        "DELETE FROM zone_versions WHERE zone_id = $1 AND (($2 - serial + 4294967296) % 4294967296) >= 2147483648",
    )
    .bind(zone_id)
    .bind(current)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}
