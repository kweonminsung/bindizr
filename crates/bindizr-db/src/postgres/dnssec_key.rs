use bindizr_core::{
    dns::Ttl,
    model::{dnssec_key::DnssecKeyId, zone::ZoneId},
};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, Pool, Postgres, Row, Transaction};

use crate::{
    LockLevel,
    error::DatabaseError,
    model::dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
};

/// Insert a DNSSEC key in the current transaction.
pub(crate) async fn create_tx(
    tx: &mut Transaction<'_, Postgres>,
    mut key: DnssecKey,
) -> Result<DnssecKey, DatabaseError> {
    let now = Utc::now();
    let result = sqlx::query(
        r#"
        INSERT INTO dnssec_keys (zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
        "#,
    )
    .bind(key.zone_id)
    .bind(key.role.as_str())
    .bind(key.algorithm.to_int())
    .bind(key.key_tag)
    .bind(&key.public_key)
    .bind(&key.private_key)
    .bind(key.state.as_str())
    .bind(key.state_changed_at)
    .bind(key.eligible_at)
    .bind(key.max_signed_ttl)
    .bind(now)
    .fetch_one(&mut **tx)
    .await?;

    key.id = DnssecKeyId::from(result.get::<i32, _>(0));
    key.created_at = now;
    Ok(key)
}

/// List DNSSEC keys for a zone in the current transaction.
pub(crate) async fn list_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
    lock_level: LockLevel,
) -> Result<Vec<DnssecKey>, DatabaseError> {
    let keys = sqlx::query_as::<_, DnssecKey>(AssertSqlSafe(format!(
        "{}{}",
        r#"
        SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl, created_at
        FROM dnssec_keys
        WHERE zone_id = $1
        ORDER BY id
        "#,
        lock_level.clause()
    )))
    .bind(zone_id)
    .fetch_all(&mut **tx)
    .await?;

    Ok(keys)
}

/// List keys in the requested state whose transition deadline has passed.
pub(crate) async fn list_by_state_eligible_before(
    pool: &Pool<Postgres>,
    state: DnssecKeyState,
    cutoff: DateTime<Utc>,
) -> Result<Vec<DnssecKey>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let keys = sqlx::query_as::<_, DnssecKey>(
        r#"
        SELECT id, zone_id, role, algorithm, key_tag, public_key, private_key, state, state_changed_at, eligible_at, max_signed_ttl, created_at
        FROM dnssec_keys
        WHERE state = $1 AND eligible_at <= $2
        ORDER BY zone_id, id
        "#,
    )
    .bind(state.as_str())
    .bind(cutoff)
    .fetch_all(&mut *conn)
    .await?;

    Ok(keys)
}

/// List zones whose keys have exceeded the policy's ZSK lifetime.
pub(crate) async fn list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
    pool: &Pool<Postgres>,
    role: DnssecKeyRole,
    state: DnssecKeyState,
    cutoff: DateTime<Utc>,
) -> Result<Vec<ZoneId>, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let zone_ids = sqlx::query_scalar::<_, ZoneId>(
        r#"
        SELECT DISTINCT k.zone_id
        FROM dnssec_keys k
        JOIN zones z ON z.id = k.zone_id
        JOIN dnssec_policies p ON p.id = z.dnssec_policy_id
        WHERE k.role = $1 AND k.state = $2
          AND p.zsk_lifetime_days > 0
          AND k.state_changed_at < $3 - make_interval(days => p.zsk_lifetime_days)
        ORDER BY k.zone_id
        "#,
    )
    .bind(role.as_str())
    .bind(state.as_str())
    .bind(cutoff)
    .fetch_all(&mut *conn)
    .await?;

    Ok(zone_ids)
}

/// Count DNSSEC keys in the requested lifecycle state.
pub(crate) async fn count_by_state(
    pool: &Pool<Postgres>,
    state: DnssecKeyState,
) -> Result<u64, DatabaseError> {
    let mut conn = pool.acquire().await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM dnssec_keys WHERE state = $1")
        .bind(state.as_str())
        .fetch_one(&mut *conn)
        .await?;

    Ok(count as u64)
}

/// Update a key's lifecycle state and transition deadlines in the current transaction.
pub(crate) async fn update_state_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: DnssecKeyId,
    state: DnssecKeyState,
    changed_at: DateTime<Utc>,
    eligible_at: DateTime<Utc>,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "UPDATE dnssec_keys SET state = $1, state_changed_at = $2, eligible_at = $3 WHERE id = $4",
    )
    .bind(state.as_str())
    .bind(changed_at)
    .bind(eligible_at)
    .bind(id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Update the maximum TTL signed by a DNSSEC key in the current transaction.
pub(crate) async fn update_max_signed_ttl_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: DnssecKeyId,
    max_signed_ttl: Ttl,
) -> Result<(), DatabaseError> {
    sqlx::query("UPDATE dnssec_keys SET max_signed_ttl = $1 WHERE id = $2")
        .bind(max_signed_ttl)
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Delete a DNSSEC key by ID in the current transaction.
pub(crate) async fn delete_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: DnssecKeyId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM dnssec_keys WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

/// Delete all DNSSEC keys for a zone in the current transaction.
pub(crate) async fn delete_by_zone_id_tx(
    tx: &mut Transaction<'_, Postgres>,
    zone_id: ZoneId,
) -> Result<(), DatabaseError> {
    sqlx::query("DELETE FROM dnssec_keys WHERE zone_id = $1")
        .bind(zone_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}
