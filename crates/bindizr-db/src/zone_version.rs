use bindizr_core::{dns::Serial, model::zone::ZoneId};
use chrono::{DateTime, Utc};

use crate::{
    Backend, Db, LockLevel, Transaction,
    error::DatabaseError,
    model::zone_version::{VersionScope, ZoneVersion},
    mysql, postgres, sqlite,
    tx::TransactionKind,
};

/// Insert or update a zone version in the current transaction.
pub async fn upsert_tx(
    tx: &mut Transaction<'_>,
    version: ZoneVersion,
) -> Result<ZoneVersion, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone_version::upsert_tx(tx, version).await,
        TransactionKind::Postgres(tx) => postgres::zone_version::upsert_tx(tx, version).await,
        TransactionKind::Sqlite(tx) => sqlite::zone_version::upsert_tx(tx, version).await,
    }
}

/// Find a zone version by zone ID and serial.
pub async fn get_by_serial(
    db: &Db,
    zone_id: ZoneId,
    serial: Serial,
) -> Result<Option<ZoneVersion>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::zone_version::get_by_serial(pool, zone_id, serial).await,
        Backend::Postgres(pool) => {
            postgres::zone_version::get_by_serial(pool, zone_id, serial).await
        }
        Backend::Sqlite(pool) => sqlite::zone_version::get_by_serial(pool, zone_id, serial).await,
    }
}

/// Versions with serial in the closed interval `[from_serial, to_serial]`;
/// an IXFR needs both endpoint SOAs, unlike the journal's half-open range.
pub async fn list_in_serial_range(
    db: &Db,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<Vec<ZoneVersion>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::zone_version::list_in_serial_range(pool, zone_id, from_serial, to_serial).await
        }
        Backend::Postgres(pool) => {
            postgres::zone_version::list_in_serial_range(pool, zone_id, from_serial, to_serial)
                .await
        }
        Backend::Sqlite(pool) => {
            sqlite::zone_version::list_in_serial_range(pool, zone_id, from_serial, to_serial).await
        }
    }
}

/// List the versions of a zone that `scope` covers, newest serial first,
/// paginated; the current serial is always listed.
pub async fn list(
    db: &Db,
    zone_id: ZoneId,
    scope: VersionScope,
    limit: u32,
    offset: u64,
) -> Result<Vec<ZoneVersion>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::zone_version::list(pool, zone_id, scope, limit, offset).await
        }
        Backend::Postgres(pool) => {
            postgres::zone_version::list(pool, zone_id, scope, limit, offset).await
        }
        Backend::Sqlite(pool) => {
            sqlite::zone_version::list(pool, zone_id, scope, limit, offset).await
        }
    }
}

/// Count the versions of a zone that `scope` covers.
pub async fn count(db: &Db, zone_id: ZoneId, scope: VersionScope) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::zone_version::count(pool, zone_id, scope).await,
        Backend::Postgres(pool) => postgres::zone_version::count(pool, zone_id, scope).await,
        Backend::Sqlite(pool) => sqlite::zone_version::count(pool, zone_id, scope).await,
    }
}

/// Read a zone version by serial consistently with mutations in the current transaction.
pub async fn get_by_serial_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    serial: Serial,
    lock_level: LockLevel,
) -> Result<Option<ZoneVersion>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone_version::get_by_serial_tx(tx, zone_id, serial, lock_level).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone_version::get_by_serial_tx(tx, zone_id, serial, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone_version::get_by_serial_tx(tx, zone_id, serial, lock_level).await
        }
    }
}

/// Prune one zone's versions older than `cutoff`, always keeping its
/// newest (the IXFR up-to-date response reads it). Returns rows deleted.
pub async fn prune_by_zone_id_older_than_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone_version::prune_by_zone_id_older_than_tx(tx, zone_id, cutoff).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone_version::prune_by_zone_id_older_than_tx(tx, zone_id, cutoff).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone_version::prune_by_zone_id_older_than_tx(tx, zone_id, cutoff).await
        }
    }
}
