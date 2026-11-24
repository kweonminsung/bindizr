//! Durable activity log rows.

use bindizr_core::model::activity_log::{ActivityLog, ActivityOperation, ActivityResult};
use chrono::{DateTime, Utc};

use crate::error::DatabaseError;
use crate::tx::TransactionKind;
use crate::{ActivityLogSortField, Backend, Db, SortOrder, Transaction, mysql, postgres, sqlite};

/// Filters and paging for the interactive activity log.
#[derive(Debug, Clone, Default)]
pub struct ActivityLogFilter {
    pub entity: Option<String>,
    pub operation: Option<ActivityOperation>,
    pub result: Option<ActivityResult>,
    pub name: Option<String>,
    pub zone_name: Option<String>,
    pub record_name: Option<String>,
    pub record_type: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub sort: ActivityLogSortField,
    pub order: SortOrder,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Insert an activity log row in the caller's transaction, assigning its id.
pub async fn create_tx(tx: &mut Transaction<'_>, log: &ActivityLog) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::activity_log::create_tx(tx, log).await,
        TransactionKind::Postgres(tx) => postgres::activity_log::create_tx(tx, log).await,
        TransactionKind::Sqlite(tx) => sqlite::activity_log::create_tx(tx, log).await,
    }
}

/// Insert a batch in input order, assigning an id to each row.
pub async fn create_many_tx(
    tx: &mut Transaction<'_>,
    logs: &[ActivityLog],
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::activity_log::create_many_tx(tx, logs).await,
        TransactionKind::Postgres(tx) => postgres::activity_log::create_many_tx(tx, logs).await,
        TransactionKind::Sqlite(tx) => sqlite::activity_log::create_many_tx(tx, logs).await,
    }
}

/// List the activity rows matching the filter, using the requested order.
pub async fn list_by_filter(
    db: &Db,
    filter: &ActivityLogFilter,
) -> Result<Vec<ActivityLog>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::activity_log::list_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::activity_log::list_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::activity_log::list_by_filter(pool, filter).await,
    }
}

/// Count all activity rows matching the filter without paging.
pub async fn count_by_filter(db: &Db, filter: &ActivityLogFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::activity_log::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::activity_log::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::activity_log::count_by_filter(pool, filter).await,
    }
}

/// Prune activity log rows before the cutoff.
pub async fn prune_older_than(db: &Db, cutoff: DateTime<Utc>) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::activity_log::prune_older_than(pool, cutoff).await,
        Backend::Postgres(pool) => postgres::activity_log::prune_older_than(pool, cutoff).await,
        Backend::Sqlite(pool) => sqlite::activity_log::prune_older_than(pool, cutoff).await,
    }
}

#[cfg(test)]
mod tests;
