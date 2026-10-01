use bindizr_core::{
    dns::name::ZoneName,
    model::{api_token::TokenId, dnssec_record::DnssecRecordId, zone::ZoneId},
};
use chrono::{DateTime, Utc};

use crate::{
    Backend, Db, LockLevel, Transaction,
    error::DatabaseError,
    model::dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    mysql, postgres, sqlite,
    tx::TransactionKind,
};

/// A derived row's rdata is wire bytes and its type a number, so only the
/// name half of a search reaches it, and value and priority not at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnssecRecordFilter {
    /// Matched as in `RecordFilter`.
    pub zone_name: Option<ZoneName>,
    pub name: Option<String>,
    /// The wire record type number, the column form.
    pub record_type: Option<i32>,
    pub ttl: Option<i32>,
    pub min_ttl: Option<i32>,
    pub max_ttl: Option<i32>,
    /// Partial match against the zone name, the owner name, and the FQDN —
    /// the name forms a derived row shares with a user one.
    pub search: Option<String>,
    /// Restrict to zones granted to this token, joined against
    /// `token_grants` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<TokenId>,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// Insert many derived records in one statement (chunked). Ids are not
/// returned.
pub async fn create_many_tx(
    tx: &mut Transaction<'_>,
    records: &[DnssecRecord],
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_record::create_many_tx(tx, records).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_record::create_many_tx(tx, records).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_record::create_many_tx(tx, records).await,
    }
}

/// List derived DNSSEC records for a zone in the current transaction.
pub async fn list_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
    lock_level: LockLevel,
) -> Result<Vec<DnssecRecord>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_record::list_tx(tx, zone_id, lock_level).await,
        TransactionKind::Postgres(tx) => {
            postgres::dnssec_record::list_tx(tx, zone_id, lock_level).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::dnssec_record::list_tx(tx, zone_id, lock_level).await
        }
    }
}

/// Delete many derived records in as few statements as the backend's bind
/// limit allows.
pub async fn delete_many_tx(
    tx: &mut Transaction<'_>,
    ids: &[DnssecRecordId],
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_record::delete_many_tx(tx, ids).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_record::delete_many_tx(tx, ids).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_record::delete_many_tx(tx, ids).await,
    }
}

/// Delete all derived DNSSEC records for a zone in the current transaction.
pub async fn delete_by_zone_id_tx(
    tx: &mut Transaction<'_>,
    zone_id: ZoneId,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_record::delete_by_zone_id_tx(tx, zone_id).await,
        TransactionKind::Postgres(tx) => {
            postgres::dnssec_record::delete_by_zone_id_tx(tx, zone_id).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::dnssec_record::delete_by_zone_id_tx(tx, zone_id).await
        }
    }
}

/// Zones holding a signed view (any derived row): the signed-zone count.
pub async fn count_zone_ids(db: &Db) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_record::count_zone_ids(pool).await,
        Backend::Postgres(pool) => postgres::dnssec_record::count_zone_ids(pool).await,
        Backend::Sqlite(pool) => sqlite::dnssec_record::count_zone_ids(pool).await,
    }
}

/// Zones holding an RRSIG that expires within their policy's re-sign
/// window after `cutoff`: the re-sign work list.
pub async fn list_zone_ids_expiring_within_refresh(
    db: &Db,
    cutoff: DateTime<Utc>,
) -> Result<Vec<ZoneId>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::dnssec_record::list_zone_ids_expiring_within_refresh(pool, cutoff).await
        }
        Backend::Postgres(pool) => {
            postgres::dnssec_record::list_zone_ids_expiring_within_refresh(pool, cutoff).await
        }
        Backend::Sqlite(pool) => {
            sqlite::dnssec_record::list_zone_ids_expiring_within_refresh(pool, cutoff).await
        }
    }
}

/// Rows expiring within their zone's policy's re-sign window after
/// `cutoff`; only RRSIG rows carry `expires_at`.
pub async fn count_expiring_within_refresh(
    db: &Db,
    cutoff: DateTime<Utc>,
) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::dnssec_record::count_expiring_within_refresh(pool, cutoff).await
        }
        Backend::Postgres(pool) => {
            postgres::dnssec_record::count_expiring_within_refresh(pool, cutoff).await
        }
        Backend::Sqlite(pool) => {
            sqlite::dnssec_record::count_expiring_within_refresh(pool, cutoff).await
        }
    }
}

/// Rows whose expiration has already passed `cutoff`: signatures no
/// resolver will accept any more.
pub async fn count_expired_before(db: &Db, cutoff: DateTime<Utc>) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_record::count_expired_before(pool, cutoff).await,
        Backend::Postgres(pool) => {
            postgres::dnssec_record::count_expired_before(pool, cutoff).await
        }
        Backend::Sqlite(pool) => sqlite::dnssec_record::count_expired_before(pool, cutoff).await,
    }
}

/// List matching derived DNSSEC records with their zone metadata.
pub async fn list_by_filter_with_zone(
    db: &Db,
    filter: DnssecRecordFilter,
) -> Result<Vec<DnssecRecordWithZone>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_record::list_by_filter_with_zone(pool, filter).await,
        Backend::Postgres(pool) => {
            postgres::dnssec_record::list_by_filter_with_zone(pool, filter).await
        }
        Backend::Sqlite(pool) => {
            sqlite::dnssec_record::list_by_filter_with_zone(pool, filter).await
        }
    }
}

/// Count derived DNSSEC records matching the filter.
pub async fn count_by_filter(db: &Db, filter: DnssecRecordFilter) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_record::count_by_filter(pool, filter).await,
        Backend::Postgres(pool) => postgres::dnssec_record::count_by_filter(pool, filter).await,
        Backend::Sqlite(pool) => sqlite::dnssec_record::count_by_filter(pool, filter).await,
    }
}
