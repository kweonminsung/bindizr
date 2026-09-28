use chrono::{DateTime, Utc};

use crate::{
    Backend, Db, LockLevel, Transaction,
    error::DatabaseError,
    model::dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
    mysql, postgres, sqlite,
    tx::TransactionKind,
};

/// Insert a DNSSEC key in the current transaction.
pub async fn create_tx(
    tx: &mut Transaction<'_>,
    key: DnssecKey,
) -> Result<DnssecKey, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_key::create_tx(tx, key).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_key::create_tx(tx, key).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_key::create_tx(tx, key).await,
    }
}

/// List DNSSEC keys for a zone in the current transaction.
pub async fn list_tx(
    tx: &mut Transaction<'_>,
    zone_id: i32,
    lock_level: LockLevel,
) -> Result<Vec<DnssecKey>, DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_key::list_tx(tx, zone_id, lock_level).await,
        TransactionKind::Postgres(tx) => {
            postgres::dnssec_key::list_tx(tx, zone_id, lock_level).await
        }
        TransactionKind::Sqlite(tx) => sqlite::dnssec_key::list_tx(tx, zone_id, lock_level).await,
    }
}

/// Keys in `state` whose stamped `eligible_at` deadline has passed `cutoff`:
/// the rollover work list.
pub async fn list_by_state_eligible_before(
    db: &Db,
    state: DnssecKeyState,
    cutoff: DateTime<Utc>,
) -> Result<Vec<DnssecKey>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::dnssec_key::list_by_state_eligible_before(pool, state, cutoff).await
        }
        Backend::Postgres(pool) => {
            postgres::dnssec_key::list_by_state_eligible_before(pool, state, cutoff).await
        }
        Backend::Sqlite(pool) => {
            sqlite::dnssec_key::list_by_state_eligible_before(pool, state, cutoff).await
        }
    }
}

/// Zone ids holding a key of `role` sitting in `state` longer than the
/// zone's policy's ZSK lifetime (0 exempts the zone): the
/// scheduled-rollover work list.
pub async fn list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
    db: &Db,
    role: DnssecKeyRole,
    state: DnssecKeyState,
    cutoff: DateTime<Utc>,
) -> Result<Vec<i32>, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => {
            mysql::dnssec_key::list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
                pool, role, state, cutoff,
            )
            .await
        }
        Backend::Postgres(pool) => {
            postgres::dnssec_key::list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
                pool, role, state, cutoff,
            )
            .await
        }
        Backend::Sqlite(pool) => {
            sqlite::dnssec_key::list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
                pool, role, state, cutoff,
            )
            .await
        }
    }
}

/// Count DNSSEC keys in the requested lifecycle state.
pub async fn count_by_state(db: &Db, state: DnssecKeyState) -> Result<u64, DatabaseError> {
    match &db.0 {
        Backend::MySql(pool) => mysql::dnssec_key::count_by_state(pool, state).await,
        Backend::Postgres(pool) => postgres::dnssec_key::count_by_state(pool, state).await,
        Backend::Sqlite(pool) => sqlite::dnssec_key::count_by_state(pool, state).await,
    }
}

/// Update a key's lifecycle state and transition deadlines in the current transaction.
pub async fn update_state_tx(
    tx: &mut Transaction<'_>,
    id: i32,
    state: DnssecKeyState,
    changed_at: DateTime<Utc>,
    eligible_at: DateTime<Utc>,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::dnssec_key::update_state_tx(tx, id, state, changed_at, eligible_at).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::dnssec_key::update_state_tx(tx, id, state, changed_at, eligible_at).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::dnssec_key::update_state_tx(tx, id, state, changed_at, eligible_at).await
        }
    }
}

/// Update the maximum TTL signed by a DNSSEC key in the current transaction.
pub async fn update_max_signed_ttl_tx(
    tx: &mut Transaction<'_>,
    id: i32,
    max_signed_ttl: i32,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => {
            mysql::dnssec_key::update_max_signed_ttl_tx(tx, id, max_signed_ttl).await
        }
        TransactionKind::Postgres(tx) => {
            postgres::dnssec_key::update_max_signed_ttl_tx(tx, id, max_signed_ttl).await
        }
        TransactionKind::Sqlite(tx) => {
            sqlite::dnssec_key::update_max_signed_ttl_tx(tx, id, max_signed_ttl).await
        }
    }
}

/// Delete a DNSSEC key by ID in the current transaction.
pub async fn delete_tx(tx: &mut Transaction<'_>, id: i32) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_key::delete_tx(tx, id).await,
        TransactionKind::Postgres(tx) => postgres::dnssec_key::delete_tx(tx, id).await,
        TransactionKind::Sqlite(tx) => sqlite::dnssec_key::delete_tx(tx, id).await,
    }
}

/// Delete all DNSSEC keys for a zone in the current transaction.
pub async fn delete_by_zone_id_tx(
    tx: &mut Transaction<'_>,
    zone_id: i32,
) -> Result<(), DatabaseError> {
    match &mut tx.0 {
        TransactionKind::MySql(tx) => mysql::dnssec_key::delete_by_zone_id_tx(tx, zone_id).await,
        TransactionKind::Postgres(tx) => {
            postgres::dnssec_key::delete_by_zone_id_tx(tx, zone_id).await
        }
        TransactionKind::Sqlite(tx) => sqlite::dnssec_key::delete_by_zone_id_tx(tx, zone_id).await,
    }
}
