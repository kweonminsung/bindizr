use crate::{Transaction, error::DatabaseError, mysql, postgres, sqlite, tx::TransactionKind};

/// Mark a zone for DNSSEC withdrawal in the current transaction.
pub async fn create_tx(tx: &mut Transaction<'_>, zone_id: i32) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_withdrawal::create_tx(tx, zone_id).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_withdrawal::create_tx(tx, zone_id).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_withdrawal::create_tx(tx, zone_id).await,
    }
}

/// Read a zone's DNSSEC withdrawal marker in the current transaction.
pub async fn get_tx(tx: &mut Transaction<'_>, zone_id: i32) -> Result<Option<i32>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_withdrawal::get_tx(tx, zone_id).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_withdrawal::get_tx(tx, zone_id).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_withdrawal::get_tx(tx, zone_id).await,
    }
}

/// Clear a zone's DNSSEC withdrawal marker in the current transaction.
pub async fn delete_tx(tx: &mut Transaction<'_>, zone_id: i32) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_withdrawal::delete_tx(tx, zone_id).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_withdrawal::delete_tx(tx, zone_id).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_withdrawal::delete_tx(tx, zone_id).await,
    }
}
