use crate::error::DatabaseError;
use crate::{
    model::zone::Zone,
    repository::{RepositoryTx, RepositoryTxKind, ZoneFilter, ZoneRepository},
};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

pub struct SqliteZoneRepository {
    pool: Pool<Sqlite>,
}

impl SqliteZoneRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for SqliteZoneRepository {
    async fn create(&self, mut zone: Zone) -> Result<Zone, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .execute(&mut *conn)
        .await?;

        zone.id = result.last_insert_rowid() as i32;
        Ok(zone)
    }

    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut zone: Zone,
    ) -> Result<Zone, DatabaseError> {
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .execute(&mut **sqlite_tx)
        .await?;

        zone.id = result.last_insert_rowid() as i32;
        Ok(zone)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE id = ?")
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut **sqlite_tx)
            .await?;

        Ok(zone)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE name = ?")
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, primary_ns, admin_email, ttl, serial, refresh, retry, expire, minimum_ttl, created_at FROM zones WHERE name = ?")
            .bind(name)
            .fetch_optional(&mut **sqlite_tx)
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
            WHERE (? IS NULL OR LOWER(name) = LOWER(?))
              AND (? IS NULL OR id = ?)
              AND (? IS NULL OR LOWER(primary_ns) = LOWER(?))
              AND (? IS NULL OR LOWER(admin_email) = LOWER(?))
              AND (? IS NULL OR ttl = ?)
              AND (? IS NULL OR ttl >= ?)
              AND (? IS NULL OR ttl <= ?)
              AND (? IS NULL OR serial = ?)
              AND (
                    ? IS NULL
                    OR LOWER(name) LIKE LOWER(?)
                    OR LOWER(primary_ns) LIKE LOWER(?)
                    OR LOWER(admin_email) LIKE LOWER(?)
              )
            ORDER BY name
            LIMIT ? OFFSET ?
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

    async fn update(&self, zone: Zone) -> Result<Zone, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE zones 
            SET name = ?, primary_ns = ?, admin_email = ?,
                ttl = ?, serial = ?, refresh = ?, retry = ?, expire = ?, minimum_ttl = ?
            WHERE id = ?
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
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        sqlx::query(
            r#"
            UPDATE zones 
            SET name = ?, primary_ns = ?, admin_email = ?,
                ttl = ?, serial = ?, refresh = ?, retry = ?, expire = ?, minimum_ttl = ?
            WHERE id = ?
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
        .execute(&mut **sqlite_tx)
        .await?;

        Ok(zone)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM zones WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let sqlite_tx = match &mut tx.0 {
            RepositoryTxKind::SQLite(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected SQLite)".to_string(),
                ));
            }
        };

        sqlx::query("DELETE FROM zones WHERE id = ?")
            .bind(id)
            .execute(&mut **sqlite_tx)
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
