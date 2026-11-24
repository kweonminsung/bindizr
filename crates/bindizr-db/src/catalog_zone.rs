use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;

use crate::error::DatabaseError;
use crate::tx::TransactionKind;
use crate::{Transaction, mysql, postgres, sqlite};

/// Lock the catalog row even on the first refresh. A new row's empty digest
/// marks it uninitialized until the same transaction stores its membership.
pub async fn upsert_tx(
    tx: &mut Transaction<'_>,
    catalog_zone_name: &ZoneName,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::catalog_zone::upsert_tx(tx, catalog_zone_name).await,
        TransactionKind::Postgres(tx) => {
            postgres::catalog_zone::upsert_tx(tx, catalog_zone_name).await
        }
        TransactionKind::Sqlite(tx) => sqlite::catalog_zone::upsert_tx(tx, catalog_zone_name).await,
    }
}

/// Store the locked catalog's membership digest and return its serial. The
/// first refresh uses `base_serial`, and later changes advance the serial.
pub async fn update_tx(
    tx: &mut Transaction<'_>,
    catalog_zone_name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::catalog_zone::update_tx(tx, catalog_zone_name, digest, base_serial).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::catalog_zone::update_tx(tx, catalog_zone_name, digest, base_serial).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::catalog_zone::update_tx(tx, catalog_zone_name, digest, base_serial).await
        }
    }
}
