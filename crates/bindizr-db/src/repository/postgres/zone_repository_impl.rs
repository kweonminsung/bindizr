use async_trait::async_trait;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

use crate::{
    error::DatabaseError,
    model::zone::Zone,
    repository::{
        LockLevel, RepositoryTx, ZoneFilter, ZoneRepository,
        sql::{like_pattern, lock_clause},
    },
};

/// PostgreSQL-backed implementation of `ZoneRepository`.
pub(crate) struct PostgresZoneRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneRepository {
    pub(crate) fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for PostgresZoneRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut zone: Zone,
    ) -> Result<Zone, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(zone.name.as_str())
        .bind(&zone.mname)
        .bind(&zone.rname)
        .bind(zone.default_ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .fetch_one(&mut **postgres_tx)
        .await?;

        zone.id = result.get::<i32, _>(0);
        Ok(zone)
    }

    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let zone = sqlx::query_as::<_, Zone>(AssertSqlSafe(format!("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, created_at FROM zones WHERE id = $1{}",lock_clause(lock_level))))
            .bind(id)
            .fetch_optional(&mut **postgres_tx)
            .await?;

        Ok(zone)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, created_at FROM zones WHERE name = $1")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(zone)
    }

    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let zone = sqlx::query_as::<_, Zone>(AssertSqlSafe(
            format!("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, created_at FROM zones WHERE name = $1{}",
            lock_clause(lock_level),
        )))
        .bind(name)
        .fetch_optional(&mut **postgres_tx)
        .await?;

        Ok(zone)
    }

    async fn list_all(&self) -> Result<Vec<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zones = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, created_at FROM zones ORDER BY name")
            .fetch_all(&mut *conn)
            .await?;

        Ok(zones)
    }

    async fn list_all_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        lock_level: LockLevel,
    ) -> Result<Vec<Zone>, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        let zones = sqlx::query_as::<_, Zone>(AssertSqlSafe(format!("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, created_at FROM zones ORDER BY name{}",lock_clause(lock_level))))
            .fetch_all(&mut **postgres_tx)
            .await?;

        Ok(zones)
    }

    async fn list_by_filter(&self, filter: ZoneFilter) -> Result<Vec<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let search = like_pattern(filter.search.as_deref());

        let zones = sqlx::query_as::<_, Zone>(
            r#"
            SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_policy_id, created_at
            FROM zones
            WHERE ($1::TEXT IS NULL OR LOWER(name) = LOWER($2))
              AND ($3::INT4 IS NULL OR id = $4)
              AND ($5::TEXT IS NULL OR LOWER(mname) = LOWER($6))
              AND ($7::TEXT IS NULL OR LOWER(rname) = LOWER($8))
              AND ($9::INT4 IS NULL OR default_ttl = $10)
              AND ($11::INT4 IS NULL OR default_ttl >= $12)
              AND ($13::INT4 IS NULL OR default_ttl <= $14)
              AND ($15::INT4 IS NULL OR serial = $16)
              AND (
                    $17::TEXT IS NULL
                    OR LOWER(name) LIKE LOWER($18) ESCAPE '\'
                    OR LOWER(mname) LIKE LOWER($19) ESCAPE '\'
                    OR LOWER(rname) LIKE LOWER($20) ESCAPE '\'
              )
              AND (
                    $23::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = $23 AND p.zone_id = zones.id)
              )
            ORDER BY name
            LIMIT $21 OFFSET $22
            "#,
        )
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(filter.id)
        .bind(filter.id)
        .bind(&filter.mname)
        .bind(&filter.mname)
        .bind(&filter.rname)
        .bind(&filter.rname)
        .bind(filter.default_ttl)
        .bind(filter.default_ttl)
        .bind(filter.min_default_ttl)
        .bind(filter.min_default_ttl)
        .bind(filter.max_default_ttl)
        .bind(filter.max_default_ttl)
        .bind(filter.serial)
        .bind(filter.serial)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(filter.limit.map(i64::from).unwrap_or(i64::MAX))
        .bind(
            filter
                .offset
                .map(|offset| i64::try_from(offset).unwrap_or(i64::MAX))
                .unwrap_or(0),
        )
        .bind(filter.scope_token_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(zones)
    }

    async fn ping(&self) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT 1 FROM zones LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
        Ok(())
    }

    async fn count_by_filter(&self, filter: ZoneFilter) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let search = like_pattern(filter.search.as_deref());

        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM zones
            WHERE ($1::TEXT IS NULL OR LOWER(name) = LOWER($2))
              AND ($3::INT4 IS NULL OR id = $4)
              AND ($5::TEXT IS NULL OR LOWER(mname) = LOWER($6))
              AND ($7::TEXT IS NULL OR LOWER(rname) = LOWER($8))
              AND ($9::INT4 IS NULL OR default_ttl = $10)
              AND ($11::INT4 IS NULL OR default_ttl >= $12)
              AND ($13::INT4 IS NULL OR default_ttl <= $14)
              AND ($15::INT4 IS NULL OR serial = $16)
              AND (
                    $17::TEXT IS NULL
                    OR LOWER(name) LIKE LOWER($18) ESCAPE '\'
                    OR LOWER(mname) LIKE LOWER($19) ESCAPE '\'
                    OR LOWER(rname) LIKE LOWER($20) ESCAPE '\'
              )
              AND (
                    $21::INT4 IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = $21 AND p.zone_id = zones.id)
              )
            "#,
        )
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(filter.id)
        .bind(filter.id)
        .bind(&filter.mname)
        .bind(&filter.mname)
        .bind(&filter.rname)
        .bind(&filter.rname)
        .bind(filter.default_ttl)
        .bind(filter.default_ttl)
        .bind(filter.min_default_ttl)
        .bind(filter.min_default_ttl)
        .bind(filter.max_default_ttl)
        .bind(filter.max_default_ttl)
        .bind(filter.serial)
        .bind(filter.serial)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(filter.scope_token_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }

    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query(
            r#"
            UPDATE zones 
            SET name = $1, mname = $2, rname = $3,
                default_ttl = $4, serial = $5, refresh = $6, retry = $7, expire = $8, minimum_ttl = $9
            WHERE id = $10
            "#,
        )
        .bind(zone.name.as_str())
        .bind(&zone.mname)
        .bind(&zone.rname)
        .bind(zone.default_ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .bind(zone.id)
        .execute(&mut **postgres_tx)
        .await?;

        Ok(zone)
    }

    async fn update_dnssec_policy_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        dnssec_policy_id: Option<i32>,
    ) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query("UPDATE zones SET dnssec_policy_id = $1 WHERE id = $2")
            .bind(dnssec_policy_id)
            .bind(zone_id)
            .execute(&mut **postgres_tx)
            .await?;

        Ok(())
    }

    async fn count_by_dnssec_policy_id(&self, dnssec_policy_id: i32) -> Result<u64, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let count =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM zones WHERE dnssec_policy_id = $1")
                .bind(dnssec_policy_id)
                .fetch_one(&mut *conn)
                .await?;

        Ok(count as u64)
    }

    async fn update_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query("UPDATE zones SET serial = $1 WHERE id = $2")
            .bind(serial)
            .bind(zone_id)
            .execute(&mut **postgres_tx)
            .await?;
        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let postgres_tx = tx.as_postgres()?;

        sqlx::query("DELETE FROM zones WHERE id = $1")
            .bind(id)
            .execute(&mut **postgres_tx)
            .await?;
        Ok(())
    }
}
