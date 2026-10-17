//! The audit log: the management changes kept so who changed what, and
//! when, reads back after the object itself is gone.

use bindizr_core::model::audit_log::{AuditEntity, AuditLog};
use chrono::{DateTime, Utc};

use crate::{
    AuditLogSortField, Backend, Db, SortOrder, Transaction, error::DatabaseError, mysql, postgres,
    sqlite, tx::TransactionKind,
};

/// Which audit log rows a listing selects and how they are ordered; paging
/// rides along.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditLogFilter {
    pub entity: Option<AuditEntity>,
    pub entity_name: Option<String>,
    /// Entries made at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Entries made before this time.
    pub until: Option<DateTime<Utc>>,
    pub sort: AuditLogSortField,
    pub order: SortOrder,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Insert an audit log row in the current transaction, the change's own.
pub async fn create_tx(tx: &mut Transaction<'_>, log: AuditLog) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::audit_log::create_tx(tx, log).await,
        TransactionKind::Postgres(tx) => postgres::audit_log::create_tx(tx, log).await,
        TransactionKind::Sqlite(tx) => sqlite::audit_log::create_tx(tx, log).await,
    }
}

/// The rows `filter` selects, in its order.
pub async fn list_by_filter(
    db: &Db,
    filter: &AuditLogFilter,
) -> Result<Vec<AuditLog>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::audit_log::list_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::audit_log::list_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::audit_log::list_by_filter(pool, filter).await,
    }
}

/// How many rows `filter` selects, its paging aside.
pub async fn count_by_filter(db: &Db, filter: &AuditLogFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::audit_log::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::audit_log::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::audit_log::count_by_filter(pool, filter).await,
    }
}

/// Delete the rows made before `cutoff`, returning how many.
pub async fn prune_older_than(db: &Db, cutoff: DateTime<Utc>) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::audit_log::prune_older_than(pool, cutoff).await,
        Backend::Postgres(pool) => postgres::audit_log::prune_older_than(pool, cutoff).await,
        Backend::Sqlite(pool) => sqlite::audit_log::prune_older_than(pool, cutoff).await,
    }
}
