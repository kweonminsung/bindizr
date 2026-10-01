use bindizr_core::{
    dns::{Serial, name::ZoneName},
    model::{api_token::TokenId, dnssec_policy::PolicyId, zone::ZoneId},
};
use chrono::{DateTime, Utc};

use crate::{
    Backend, Db, LockLevel, Transaction,
    error::DatabaseError,
    model::zone::Zone,
    mysql, postgres,
    sql::{SortOrder, ZoneSortField},
    sqlite,
    tx::TransactionKind,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZoneFilter {
    pub name: Option<String>,
    pub id: Option<ZoneId>,
    pub mname: Option<String>,
    pub rname: Option<String>,
    pub default_ttl: Option<i32>,
    pub min_default_ttl: Option<i32>,
    pub max_default_ttl: Option<i32>,
    pub serial: Option<Serial>,
    pub min_serial: Option<Serial>,
    pub max_serial: Option<Serial>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    /// `Some(true)` keeps the zones signing under a policy, `Some(false)`
    /// the rest.
    pub signed: Option<bool>,
    /// `Some(true)` keeps the zones the DNS plane serves, `Some(false)` the
    /// disabled ones.
    pub enabled: Option<bool>,
    pub search: Option<String>,
    /// Restrict to zones granted to this token, joined against
    /// `token_grants` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<TokenId>,
    pub sort: ZoneSortField,
    pub order: SortOrder,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Insert a zone in the current transaction.
pub async fn create_tx(tx: &mut Transaction<'_>, zone: Zone) -> Result<Zone, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone::create_tx(tx, zone).await,
        TransactionKind::Postgres(tx) => postgres::zone::create_tx(tx, zone).await,
        TransactionKind::Sqlite(tx) => sqlite::zone::create_tx(tx, zone).await,
    }
}

/// Find a zone by ID in the current transaction.
pub async fn get_tx(
    tx: &mut Transaction<'_>,
    id: ZoneId,
    lock_level: LockLevel,
) -> Result<Option<Zone>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone::get_tx(tx, id, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::zone::get_tx(tx, id, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::zone::get_tx(tx, id, lock_level).await,
    }
}

/// Find a zone by name.
pub async fn get_by_name(db: &Db, name: &ZoneName) -> Result<Option<Zone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::zone::get_by_name(pool, name).await,
        Backend::Postgres(pool) => postgres::zone::get_by_name(pool, name).await,
        Backend::Sqlite(pool) => sqlite::zone::get_by_name(pool, name).await,
    }
}

/// Find a zone by name in the current transaction.
pub async fn get_by_name_tx(
    tx: &mut Transaction<'_>,
    name: &ZoneName,
    lock_level: LockLevel,
) -> Result<Option<Zone>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone::get_by_name_tx(tx, name, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::zone::get_by_name_tx(tx, name, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::zone::get_by_name_tx(tx, name, lock_level).await,
    }
}

/// List all zones.
pub async fn list_all(db: &Db) -> Result<Vec<Zone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::zone::list_all(pool).await,
        Backend::Postgres(pool) => postgres::zone::list_all(pool).await,
        Backend::Sqlite(pool) => sqlite::zone::list_all(pool).await,
    }
}

/// List all zones in the current transaction.
pub async fn list_all_tx(
    tx: &mut Transaction<'_>,
    lock_level: LockLevel,
) -> Result<Vec<Zone>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone::list_all_tx(tx, lock_level).await,
        TransactionKind::Postgres(tx) => postgres::zone::list_all_tx(tx, lock_level).await,
        TransactionKind::Sqlite(tx) => sqlite::zone::list_all_tx(tx, lock_level).await,
    }
}

/// List zones matching the filter.
pub async fn list_by_filter(db: &Db, filter: ZoneFilter) -> Result<Vec<Zone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::zone::list_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::zone::list_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::zone::list_by_filter(pool, filter).await,
    }
}

/// Count zones matching the filter.
pub async fn count_by_filter(db: &Db, filter: ZoneFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::zone::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::zone::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::zone::count_by_filter(pool, filter).await,
    }
}

/// Limit-1 probe of the zones table; health checks must stay cheap on
/// large tables.
pub async fn ping(db: &Db) -> Result<(), DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::zone::ping(pool).await,
        Backend::Postgres(pool) => postgres::zone::ping(pool).await,
        Backend::Sqlite(pool) => sqlite::zone::ping(pool).await,
    }
}

/// Full-row update, except the DNSSEC-owned `dnssec_policy_id` and
/// `parent_ns_addrs`: ordinary zone updates cannot clobber them.
pub async fn update_tx(tx: &mut Transaction<'_>, zone: Zone) -> Result<Zone, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone::update_tx(tx, zone).await,
        TransactionKind::Postgres(tx) => postgres::zone::update_tx(tx, zone).await,
        TransactionKind::Sqlite(tx) => sqlite::zone::update_tx(tx, zone).await,
    }
}

/// Set only `dnssec_policy_id`, leaving the zone's other columns
/// untouched; `None` marks the zone unsigned.
pub async fn update_dnssec_policy_id_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    dnssec_policy_id: Option<PolicyId>,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone::update_dnssec_policy_id_tx(tx, zone_id, dnssec_policy_id).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone::update_dnssec_policy_id_tx(tx, zone_id, dnssec_policy_id).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone::update_dnssec_policy_id_tx(tx, zone_id, dnssec_policy_id).await
        }
    }
}

/// Set only `parent_ns_addrs`, leaving the zone's other columns
/// untouched; `None` clears the configured parent servers.
pub async fn update_parent_ns_addrs_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    parent_ns_addrs: Option<&str>,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::zone::update_parent_ns_addrs_tx(tx, zone_id, parent_ns_addrs).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::zone::update_parent_ns_addrs_tx(tx, zone_id, parent_ns_addrs).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::zone::update_parent_ns_addrs_tx(tx, zone_id, parent_ns_addrs).await
        }
    }
}

/// Zones signed under the policy: the in-use check before a delete.
pub async fn count_by_dnssec_policy_id(
    db: &Db,
    dnssec_policy_id: PolicyId,
) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::zone::count_by_dnssec_policy_id(pool, dnssec_policy_id).await
        }
        Backend::Postgres(pool) => {
            postgres::zone::count_by_dnssec_policy_id(pool, dnssec_policy_id).await
        }
        Backend::Sqlite(pool) => {
            sqlite::zone::count_by_dnssec_policy_id(pool, dnssec_policy_id).await
        }
    }
}

/// Bump only the serial, leaving the zone's other columns untouched.
pub async fn update_serial_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    serial: Serial,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone::update_serial_tx(tx, zone_id, serial).await,
        TransactionKind::Postgres(tx) => {
            postgres::zone::update_serial_tx(tx, zone_id, serial).await
        }
        TransactionKind::Sqlite(tx) => sqlite::zone::update_serial_tx(tx, zone_id, serial).await,
    }
}

/// Delete a zone by ID in the current transaction.
pub async fn delete_tx(tx: &mut Transaction<'_>, id: ZoneId) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::zone::delete_tx(tx, id).await,
        TransactionKind::Postgres(tx) => postgres::zone::delete_tx(tx, id).await,
        TransactionKind::Sqlite(tx) => sqlite::zone::delete_tx(tx, id).await,
    }
}
