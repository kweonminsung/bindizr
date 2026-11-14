use bindizr_core::dns::Serial;
use bindizr_core::dns::name::ZoneName;

use crate::error::DatabaseError;
use crate::tx::TransactionKind;
use crate::{Transaction, mysql, postgres, sqlite};

/// Upsert the catalog digest, advancing the serial only when `digest` changed;
/// return the serial in effect after the upsert.
pub async fn upsert_tx(
    tx: &mut Transaction<'_>,
    name: &ZoneName,
    digest: &str,
    base_serial: Serial,
) -> Result<Serial, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::catalog_zone::upsert_tx(tx, name, digest, base_serial).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::catalog_zone::upsert_tx(tx, name, digest, base_serial).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::catalog_zone::upsert_tx(tx, name, digest, base_serial).await
        }
    }
}
