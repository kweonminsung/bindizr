use crate::database::error::DatabaseError;
use crate::database::{
    model::zone::Zone,
    repository::{RepositoryTx, RepositoryTxKind, ZoneRepository},
};
use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};

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

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE name = $1")
            .bind(name)
            .fetch_optional(&mut *conn)
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
