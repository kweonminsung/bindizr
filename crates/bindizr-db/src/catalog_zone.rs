use crate::{Transaction, error::DatabaseError, mysql, postgres, sqlite, tx::TransactionKind};

/// The serial advances only when `digest` changed; returns the serial in
/// effect after the upsert.
pub async fn upsert_tx(
    tx: &mut Transaction<'_>,
    name: &str,
    digest: &str,
    base_serial: i32,
) -> Result<i32, DatabaseError> {
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
