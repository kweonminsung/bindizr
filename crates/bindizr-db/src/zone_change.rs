use bindizr_core::dns::Serial;
use bindizr_core::model::zone::ZoneId;
use chrono::{DateTime, Utc};

use crate::error::DatabaseError;
use crate::model::zone_change::ZoneChange;
use crate::tx::TransactionKind;
use crate::{LockLevel, Transaction, mysql, postgres, sqlite};

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

/// How many rows `list_between_serials` would return, so a caller can
/// weigh the delta before loading it.
pub async fn count_between_serials_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    from_serial: Serial,
    to_serial: Serial,
) -> Result<u64, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone_change::count_between_serials_tx(tx, zone_id, from_serial, to_serial).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone_change::count_between_serials_tx(tx, zone_id, from_serial, to_serial)
                .await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone_change::count_between_serials_tx(tx, zone_id, from_serial, to_serial).await
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

/// Delete expired whole serials, retaining a contiguous IXFR chain.
/// Older requests use AXFR; return the deleted row count.
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

/// Drop history outside the unambiguous RFC 1982 half-range behind the current serial.
pub async fn prune_outside_serial_window_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    current: Serial,
) -> Result<u64, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone_change::prune_outside_serial_window_tx(tx, zone_id, current).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone_change::prune_outside_serial_window_tx(tx, zone_id, current).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone_change::prune_outside_serial_window_tx(tx, zone_id, current).await
        }
    }
}
