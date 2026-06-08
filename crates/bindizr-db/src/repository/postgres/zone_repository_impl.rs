use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

use crate::{
    error::DatabaseError,
    model::zone::Zone,
    repository::{RepositoryTx, RepositoryTxKind, ZoneFilter, ZoneRepository},
};

pub struct PostgresZoneRepository {
    pool: Pool<Postgres>,
}

impl PostgresZoneRepository {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for PostgresZoneRepository {
    async fn create(&self, mut zone: Zone) -> Result<Zone, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .fetch_one(&mut *conn)
        .await?;

        zone.id = result.get::<i32, _>(0);

        Ok(zone)
    }

    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut zone: Zone,
    ) -> Result<Zone, DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
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

    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(zone)
    }

    async fn get_by_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
    ) -> Result<Option<Zone>, DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut **postgres_tx)
            .await?;

        Ok(zone)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE name = $1")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(zone)
    }

    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
    ) -> Result<Option<Zone>, DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        let zone = sqlx::query_as::<_, Zone>(
            "SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE name = $1 FOR UPDATE",
        )
        .bind(name)
        .fetch_optional(&mut **postgres_tx)
        .await?;

        Ok(zone)
    }

    async fn get_all(&self) -> Result<Vec<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zones = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones ORDER BY name")
            .fetch_all(&mut *conn)
            .await?;

        Ok(zones)
    }

    async fn get_by_filter(&self, filter: ZoneFilter) -> Result<Vec<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let search = like_pattern(filter.search.as_deref());

        let zones = sqlx::query_as::<_, Zone>(
            r#"
            SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at
            FROM zones
            WHERE ($1::TEXT IS NULL OR LOWER(name) = LOWER($2))
              AND ($3::INT4 IS NULL OR id = $4)
              AND ($5::TEXT IS NULL OR LOWER(primary_ns) = LOWER($6))
              AND ($7::TEXT IS NULL OR LOWER(admin_email) = LOWER($8))
              AND ($9::INT4 IS NULL OR ttl = $10)
              AND ($11::INT4 IS NULL OR ttl >= $12)
              AND ($13::INT4 IS NULL OR ttl <= $14)
              AND ($15::INT4 IS NULL OR serial = $16)
              AND (
                    $17::TEXT IS NULL
                    OR LOWER(name) LIKE LOWER($18)
                    OR LOWER(primary_ns) LIKE LOWER($19)
                    OR LOWER(admin_email) LIKE LOWER($20)
              )
            ORDER BY name
            LIMIT $21 OFFSET $22
            "#,
        )
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(filter.id)
        .bind(filter.id)
        .bind(&filter.primary_ns)
        .bind(&filter.primary_ns)
        .bind(&filter.admin_email)
        .bind(&filter.admin_email)
        .bind(filter.ttl)
        .bind(filter.ttl)
        .bind(filter.min_ttl)
        .bind(filter.min_ttl)
        .bind(filter.max_ttl)
        .bind(filter.max_ttl)
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
        .fetch_all(&mut *conn)
        .await?;

        Ok(zones)
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
              AND ($5::TEXT IS NULL OR LOWER(primary_ns) = LOWER($6))
              AND ($7::TEXT IS NULL OR LOWER(admin_email) = LOWER($8))
              AND ($9::INT4 IS NULL OR ttl = $10)
              AND ($11::INT4 IS NULL OR ttl >= $12)
              AND ($13::INT4 IS NULL OR ttl <= $14)
              AND ($15::INT4 IS NULL OR serial = $16)
              AND (
                    $17::TEXT IS NULL
                    OR LOWER(name) LIKE LOWER($18)
                    OR LOWER(primary_ns) LIKE LOWER($19)
                    OR LOWER(admin_email) LIKE LOWER($20)
              )
            "#,
        )
        .bind(&filter.name)
        .bind(&filter.name)
        .bind(filter.id)
        .bind(filter.id)
        .bind(&filter.primary_ns)
        .bind(&filter.primary_ns)
        .bind(&filter.admin_email)
        .bind(&filter.admin_email)
        .bind(filter.ttl)
        .bind(filter.ttl)
        .bind(filter.min_ttl)
        .bind(filter.min_ttl)
        .bind(filter.max_ttl)
        .bind(filter.max_ttl)
        .bind(filter.serial)
        .bind(filter.serial)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .bind(&search)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count as u64)
    }

    async fn update(&self, zone: Zone) -> Result<Zone, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE zones 
            SET name = $1, primary_ns = $2, admin_email = $3,
                ttl = $4, serial = $5, refresh = $6, retry = $7, expire = $8, minimum_ttl = $9
            WHERE id = $10
            "#,
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
        .bind(zone.serial)
        .bind(zone.refresh)
        .bind(zone.retry)
        .bind(zone.expire)
        .bind(zone.minimum_ttl)
        .bind(zone.id)
        .execute(&mut *conn)
        .await?;

        Ok(zone)
    }

    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone: Zone,
    ) -> Result<Zone, DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        sqlx::query(
            r#"
            UPDATE zones 
            SET name = $1, primary_ns = $2, admin_email = $3,
                ttl = $4, serial = $5, refresh = $6, retry = $7, expire = $8, minimum_ttl = $9
            WHERE id = $10
            "#,
        )
        .bind(&zone.name)
        .bind(&zone.primary_ns)
        .bind(&zone.admin_email)
        .bind(zone.ttl)
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

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zones WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let postgres_tx = match &mut tx.0 {
            RepositoryTxKind::PostgreSQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected PostgreSQL)".to_string(),
                ));
            }
        };

        sqlx::query("DELETE FROM zones WHERE id = $1")
            .bind(id)
            .execute(&mut **postgres_tx)
            .await?;
        Ok(())
    }
}

fn like_pattern(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{}%", value))
}
