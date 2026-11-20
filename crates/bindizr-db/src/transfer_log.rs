//! The transfer log: every transfer Bindizr answered, refused, or failed, by
//! client address and zone.

use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::transfer::{TransferLog, TransferLogWithZone, TransferResult};
use chrono::{DateTime, Utc};

use crate::error::DatabaseError;
use crate::sql::{SortOrder, TransferLogSortField};
use crate::{Backend, Db, mysql, postgres, sqlite};

/// Which transfer log rows a listing selects and how they are ordered;
/// paging rides along.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferLogFilter {
    /// Transfers answered to one of these addresses; any address when absent.
    pub client_addrs: Option<Vec<String>>,
    pub zone_name: Option<ZoneName>,
    pub result: Option<TransferResult>,
    /// Transfers answered at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Transfers answered before this time.
    pub until: Option<DateTime<Utc>>,
    pub sort: TransferLogSortField,
    pub order: SortOrder,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

impl Default for TransferLogFilter {
    /// Select every row, newest first: the log's natural order.
    fn default() -> Self {
        Self {
            client_addrs: None,
            zone_name: None,
            result: None,
            since: None,
            until: None,
            sort: TransferLogSortField::default(),
            order: SortOrder::Desc,
            limit: None,
            offset: None,
        }
    }
}

/// Append a transfer log row.
pub async fn create(db: &Db, log: TransferLog) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::transfer_log::create(pool, log).await,
        Backend::Postgres(pool) => postgres::transfer_log::create(pool, log).await,
        Backend::Sqlite(pool) => sqlite::transfer_log::create(pool, log).await,
    }
}

/// List the rows `filter` selects, in its order, with zone names.
pub async fn list_by_filter_with_zone(
    db: &Db,
    filter: &TransferLogFilter,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::transfer_log::list_by_filter_with_zone(pool, filter).await,
        Backend::Postgres(pool) => {
            postgres::transfer_log::list_by_filter_with_zone(pool, filter).await
        }
        Backend::Sqlite(pool) => sqlite::transfer_log::list_by_filter_with_zone(pool, filter).await,
    }
}

/// Count the rows `filter` selects, its paging aside.
pub async fn count_by_filter(db: &Db, filter: &TransferLogFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::transfer_log::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::transfer_log::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::transfer_log::count_by_filter(pool, filter).await,
    }
}

/// List the newest row of each zone any of `client_addrs` asked for, with
/// zone names: newest by `served_at`, then id, as the listings sort.
pub async fn list_by_client_addrs_with_zone_latest_per_zone(
    db: &Db,
    client_addrs: &[String],
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::transfer_log::list_by_client_addrs_with_zone_latest_per_zone(pool, client_addrs)
                .await
        }
        Backend::Postgres(pool) => {
            postgres::transfer_log::list_by_client_addrs_with_zone_latest_per_zone(
                pool,
                client_addrs,
            )
            .await
        }
        Backend::Sqlite(pool) => {
            sqlite::transfer_log::list_by_client_addrs_with_zone_latest_per_zone(pool, client_addrs)
                .await
        }
    }
}

/// Prune the rows answered before `cutoff`, returning how many. The newest row
/// of each client address and zone stays whatever its age: it is the last
/// transfer the status reports read.
pub async fn prune_older_than(db: &Db, cutoff: DateTime<Utc>) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::transfer_log::prune_older_than(pool, cutoff).await,
        Backend::Postgres(pool) => postgres::transfer_log::prune_older_than(pool, cutoff).await,
        Backend::Sqlite(pool) => sqlite::transfer_log::prune_older_than(pool, cutoff).await,
    }
}
