use bindizr_core::dns::Serial;
use bindizr_core::model::change::ChangeActor;
use bindizr_core::model::zone::ZoneId;
use bindizr_core::model::zone_version::{VersionFilter, ZoneVersion};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Sqlite, Transaction};

use crate::LockLevel;
use crate::error::DatabaseError;

/// Exclude past versions whose nonempty journal contains only derived changes.
/// Bind one extra zone id to keep the current-serial subquery uncorrelated.
const EXCLUDE_PAST_SIGNER_ONLY_FILTER: &str = r#"
              AND (
                  zone_versions.serial = (SELECT zones.serial FROM zones WHERE zones.id = ?)
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
    tx: &mut Transaction<'_, Sqlite>,
    version: ZoneVersion,
) -> Result<(), DatabaseError> {
    let (changed_by_kind, changed_by_name) = version
        .changed_by
        .as_ref()
        .map(ChangeActor::as_columns)
        .unzip();

    sqlx::query(
        r#"
        INSERT INTO zone_versions (zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(zone_id, serial)
        DO UPDATE SET
            mname = excluded.mname,
            rname = excluded.rname,
            default_ttl = excluded.default_ttl,
            refresh = excluded.refresh,
            retry = excluded.retry,
            expire = excluded.expire,
            minimum_ttl = excluded.minimum_ttl,
            change_source = excluded.change_source,
            changed_by_kind = excluded.changed_by_kind,
            changed_by_name = excluded.changed_by_name
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
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// List the versions with serial in the closed interval `[from_serial,
/// to_serial]`; an IXFR needs both endpoint SOAs, unlike the journal's
/// half-open range.
pub(crate) async fn list_in_serial_range_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<Vec<ZoneVersion>, DatabaseError> {
    let versions = sqlx::query_as::<_, ZoneVersion>(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at
        FROM zone_versions
        WHERE zone_id = ? AND ((serial >= ? AND serial <= ?) OR (? > ? AND (serial >= ? OR serial <= ?)))
        "#,
    )
    .bind(zone_id)
    .bind(from_serial)
    .bind(to_serial)
    .bind(from_serial)
    .bind(to_serial)
    .bind(from_serial)
    .bind(to_serial)
    .fetch_all(&mut **tx)
    .await?;

    Ok(versions)
}

/// List the versions of a zone that `filter` covers, newest version first,
/// paginated; the current serial is always listed.
pub(crate) async fn list_by_filter(
    pool: &Pool<Sqlite>,
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
    let mut query = sqlx::query_as::<_, ZoneVersion>(AssertSqlSafe(format!(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at
        FROM zone_versions
        WHERE zone_id = ?{predicate}
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        "#
    )))
    .bind(zone_id);

    if filter == VersionFilter::ExcludePastSignerOnly {
        query = query.bind(zone_id);
    }

    let versions = query
        .bind(limit.map_or(i64::MAX, i64::from))
        .bind(offset.map_or(0, |offset| i64::try_from(offset).unwrap_or(i64::MAX)))
        .fetch_all(&mut *connection)
        .await?;

    Ok(versions)
}

/// Count the versions of a zone that `filter` covers.
pub(crate) async fn count_by_filter(
    pool: &Pool<Sqlite>,
    zone_id: ZoneId,
    filter: VersionFilter,
) -> Result<u64, DatabaseError> {
    let mut connection = pool.acquire().await?;

    let predicate = match filter {
        VersionFilter::ExcludePastSignerOnly => EXCLUDE_PAST_SIGNER_ONLY_FILTER,
        VersionFilter::All => "",
    };
    let mut query = sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM zone_versions WHERE zone_id = ?{predicate}"
    )))
    .bind(zone_id);

    if filter == VersionFilter::ExcludePastSignerOnly {
        query = query.bind(zone_id);
    }

    let count = query.fetch_one(&mut *connection).await?;

    Ok(count as u64)
}

/// Get a zone version by serial consistently with mutations in the current
/// transaction.
pub(crate) async fn get_by_serial_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    serial: Serial,
    _lock_level: LockLevel,
) -> Result<Option<ZoneVersion>, DatabaseError> {
    let version = sqlx::query_as::<_, ZoneVersion>(
        r#"
        SELECT id, zone_id, serial, mname, rname, default_ttl, refresh, retry, expire, minimum_ttl, change_source, changed_by_kind, changed_by_name, created_at
        FROM zone_versions
        WHERE zone_id = ? AND serial = ?
        "#,
    )
    .bind(zone_id)
    .bind(serial)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(version)
}

/// Prune one zone's versions older than `cutoff`, always keeping its newest
/// (the IXFR up-to-date response reads it). Returns rows deleted.
pub(crate) async fn prune_by_zone_id_older_than_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    // Retain the newest version for up-to-date IXFR responses.
    // SQLite sorts sqlx's RFC 3339 timestamp text chronologically.
    let result = sqlx::query(
        r#"
        DELETE FROM zone_versions
        WHERE zone_id = ? AND created_at < ?
          AND serial != (SELECT serial FROM zones WHERE id = ?)
        "#,
    )
    .bind(zone_id)
    .bind(cutoff)
    .bind(zone_id)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}

/// Prune history outside the unambiguous RFC 1982 half-range behind the current serial.
pub(crate) async fn prune_by_zone_id_outside_serial_window_tx(
    tx: &mut Transaction<'_, Sqlite>,
    zone_id: ZoneId,
    current: Serial,
) -> Result<u64, DatabaseError> {
    let result = sqlx::query(
        "DELETE FROM zone_versions WHERE zone_id = ? AND ((? - serial + 4294967296) % 4294967296) >= 2147483648",
    )
    .bind(zone_id)
    .bind(current)
    .execute(&mut **tx)
    .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests;
