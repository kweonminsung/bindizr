//! The transfer log: every transfer Bindizr answered, refused, or failed, by
//! client address and zone.

use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::transfer::{TransferLog, TransferLogWithZone};
use chrono::{DateTime, Utc};

use crate::error::DatabaseError;
use crate::{Backend, Db, mysql, postgres, sqlite};

/// Which of one client address's transfer log rows a listing selects.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransferLogFilter {
    pub zone_name: Option<ZoneName>,
    /// Transfers answered at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Transfers answered before this time.
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
}

/// Append a transfer log row.
pub async fn create(db: &Db, log: TransferLog) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::transfer_log::create(pool, log).await,
        Backend::Postgres(pool) => postgres::transfer_log::create(pool, log).await,
        Backend::Sqlite(pool) => sqlite::transfer_log::create(pool, log).await,
    }
}

/// List the rows of a client address `filter` selects, newest first, with zone
/// names.
pub async fn list_by_client_addr_and_filter_with_zone(
    db: &Db,
    client_addr: &str,
    filter: &TransferLogFilter,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::transfer_log::list_by_client_addr_and_filter_with_zone(pool, client_addr, filter)
                .await
        }
        Backend::Postgres(pool) => {
            postgres::transfer_log::list_by_client_addr_and_filter_with_zone(
                pool,
                client_addr,
                filter,
            )
            .await
        }
        Backend::Sqlite(pool) => {
            sqlite::transfer_log::list_by_client_addr_and_filter_with_zone(
                pool,
                client_addr,
                filter,
            )
            .await
        }
    }
}

/// List the newest row of each zone a client address asked for, with zone
/// names.
pub async fn list_by_client_addr_with_zone_latest_per_zone(
    db: &Db,
    client_addr: &str,
) -> Result<Vec<TransferLogWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::transfer_log::list_by_client_addr_with_zone_latest_per_zone(pool, client_addr)
                .await
        }
        Backend::Postgres(pool) => {
            postgres::transfer_log::list_by_client_addr_with_zone_latest_per_zone(pool, client_addr)
                .await
        }
        Backend::Sqlite(pool) => {
            sqlite::transfer_log::list_by_client_addr_with_zone_latest_per_zone(pool, client_addr)
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
