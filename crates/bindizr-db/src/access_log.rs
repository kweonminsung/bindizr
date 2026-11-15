//! The access log: every management API request and nsupdate Bindizr
//! answered, who made it, and how it ended.

use bindizr_core::model::access_log::{AccessLog, AccessResult, AccessSource};
use chrono::{DateTime, Utc};

use crate::error::DatabaseError;
use crate::{Backend, Db, mysql, postgres, sqlite};

/// Which access log rows a listing selects; paging rides along.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccessLogFilter {
    pub source: Option<AccessSource>,
    pub result: Option<AccessResult>,
    /// Requests made with the token or TSIG key of this name.
    pub caller_name: Option<String>,
    pub client_addr: Option<String>,
    /// Requests made at or after this time.
    pub since: Option<DateTime<Utc>>,
    /// Requests made before this time.
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Append an access log row.
pub async fn create(db: &Db, log: &AccessLog) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::access_log::create(pool, log).await,
        Backend::Postgres(pool) => postgres::access_log::create(pool, log).await,
        Backend::Sqlite(pool) => sqlite::access_log::create(pool, log).await,
    }
}

/// List the rows `filter` selects, newest first.
pub async fn list_by_filter(
    db: &Db,
    filter: &AccessLogFilter,
) -> Result<Vec<AccessLog>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::access_log::list_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::access_log::list_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::access_log::list_by_filter(pool, filter).await,
    }
}

/// Count the rows `filter` selects, its paging aside.
pub async fn count_by_filter(db: &Db, filter: &AccessLogFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::access_log::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::access_log::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::access_log::count_by_filter(pool, filter).await,
    }
}

/// Prune the rows made before `cutoff`, returning how many.
pub async fn prune_older_than(db: &Db, cutoff: DateTime<Utc>) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::access_log::prune_older_than(pool, cutoff).await,
        Backend::Postgres(pool) => postgres::access_log::prune_older_than(pool, cutoff).await,
        Backend::Sqlite(pool) => sqlite::access_log::prune_older_than(pool, cutoff).await,
    }
}
