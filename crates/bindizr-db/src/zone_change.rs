use bindizr_core::{dns::Serial, model::zone::ZoneId};
use chrono::{DateTime, Utc};

use crate::{
    Backend, Db, LockLevel, Transaction, error::DatabaseError, model::zone_change::ZoneChange,
    mysql, postgres, sqlite, tx::TransactionKind,
};

/// Insert many zone changes in one statement (chunked). Ids are not returned.
pub async fn create_many_tx(
    tx: &mut Transaction<'_>,
    changes: &[ZoneChange],
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone_change::create_many_tx(tx, changes).await,
        TransactionKind::Postgres(tx) => postgres::zone_change::create_many_tx(tx, changes).await,
        TransactionKind::Sqlite(tx) => sqlite::zone_change::create_many_tx(tx, changes).await,
    }
}

/// Journal rows with serial in `(from_serial, to_serial]` — the IXFR delta
/// half-open interval: changes strictly after `from_serial`.
pub async fn list_between_serials(
    db: &Db,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<Vec<ZoneChange>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::zone_change::list_between_serials(pool, zone_id, from_serial, to_serial).await
        }
        Backend::Postgres(pool) => {
            postgres::zone_change::list_between_serials(pool, zone_id, from_serial, to_serial).await
        }
        Backend::Sqlite(pool) => {
            sqlite::zone_change::list_between_serials(pool, zone_id, from_serial, to_serial).await
        }
    }
}

/// How many rows `list_between_serials` would return, so a caller can
/// weigh the delta before loading it.
pub async fn count_between_serials(
    db: &Db,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::zone_change::count_between_serials(pool, zone_id, from_serial, to_serial).await
        }
        Backend::Postgres(pool) => {
            postgres::zone_change::count_between_serials(pool, zone_id, from_serial, to_serial)
                .await
        }
        Backend::Sqlite(pool) => {
            sqlite::zone_change::count_between_serials(pool, zone_id, from_serial, to_serial).await
        }
    }
}

/// Read journal entries in `(from_serial, to_serial]` consistently with mutations in the
/// current transaction.
pub async fn list_between_serials_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
    lock_level: LockLevel,
) -> Result<Vec<ZoneChange>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone_change::list_between_serials_tx(
                tx,
                zone_id,
                from_serial,
                to_serial,
                lock_level,
            )
            .await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone_change::list_between_serials_tx(
                tx,
                zone_id,
                from_serial,
                to_serial,
                lock_level,
            )
            .await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone_change::list_between_serials_tx(
                tx,
                zone_id,
                from_serial,
                to_serial,
                lock_level,
            )
            .await
        }
    }
}

/// Prune one zone's journal rows older than `cutoff`, whole serials at a
/// time so the remaining chain stays contiguous; requests below it fall
/// back to AXFR. Returns the number of rows deleted.
pub async fn prune_by_zone_id_older_than_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone_change::prune_by_zone_id_older_than_tx(tx, zone_id, cutoff).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone_change::prune_by_zone_id_older_than_tx(tx, zone_id, cutoff).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone_change::prune_by_zone_id_older_than_tx(tx, zone_id, cutoff).await
        }
    }
}
