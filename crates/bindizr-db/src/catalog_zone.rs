use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;

use crate::error::DatabaseError;
use crate::tx::TransactionKind;
use crate::{LockLevel, Transaction, mysql, postgres, sqlite};

/// Find the catalog's stored serial, locking its row at `lock_level`.
pub async fn find_serial_tx(
    tx: &mut Transaction<'_>,
    catalog_zone_name: &ZoneName,
    lock_level: LockLevel,
) -> Result<Option<Serial>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::catalog_zone::find_serial_tx(tx, catalog_zone_name, lock_level).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::catalog_zone::find_serial_tx(tx, catalog_zone_name, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::catalog_zone::find_serial_tx(tx, catalog_zone_name, lock_level).await
        }
    }
}

/// Upsert the catalog digest, advancing the serial only when `digest` changed;
/// return the serial in effect after the upsert.
pub async fn upsert_tx(
    tx: &mut Transaction<'_>,
    catalog_zone_name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::catalog_zone::upsert_tx(tx, catalog_zone_name, digest, base_serial).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::catalog_zone::upsert_tx(tx, catalog_zone_name, digest, base_serial).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::catalog_zone::upsert_tx(tx, catalog_zone_name, digest, base_serial).await
        }
    }
}
