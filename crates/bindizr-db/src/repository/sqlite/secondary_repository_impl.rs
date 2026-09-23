use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::secondary::Secondary,
    repository::{LockLevel, RepositoryTx, SecondaryRepository},
};

pub(crate) struct SqliteSecondaryRepository {
    pool: Pool<Sqlite>,
}

impl SqliteSecondaryRepository {
    /// Create a repository for secondaries using the supplied pool.
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SecondaryRepository for SqliteSecondaryRepository {
    /// Insert a secondary.
    async fn create(&self, mut secondary: Secondary) -> Result<Secondary, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let now = Utc::now();
        let result = sqlx::query(
            r#"
            INSERT INTO secondaries (name, address, enabled, created_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&secondary.name)
        .bind(&secondary.address)
        .bind(secondary.enabled)
        .bind(now)
        .execute(&mut *conn)
        .await?;

        secondary.id = result.last_insert_rowid() as i32;
        secondary.created_at = now;
        Ok(secondary)
    }

    /// Find a secondary by name.
    async fn get_by_name(&self, name: &str) -> Result<Option<Secondary>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let secondary = sqlx::query_as::<_, Secondary>(
            "SELECT id, name, address, enabled, created_at FROM secondaries WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(secondary)
    }

    /// Find a secondary by name in the current transaction.
    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        _lock_level: LockLevel,
    ) -> Result<Option<Secondary>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let secondary = sqlx::query_as::<_, Secondary>(
            "SELECT id, name, address, enabled, created_at FROM secondaries WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&mut **sqlite_tx)
        .await?;

        Ok(secondary)
    }

    /// Find a secondary by address.
    async fn get_by_address(&self, address: &str) -> Result<Option<Secondary>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let secondary = sqlx::query_as::<_, Secondary>(
            "SELECT id, name, address, enabled, created_at FROM secondaries WHERE address = ?",
        )
        .bind(address)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(secondary)
    }

    /// List all secondaries, disabled ones included.
    async fn list_all(&self) -> Result<Vec<Secondary>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let secondaries = sqlx::query_as::<_, Secondary>(
            "SELECT id, name, address, enabled, created_at FROM secondaries ORDER BY name",
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(secondaries)
    }

    /// Write the address and enabled flag; the name is fixed at creation.
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        secondary: Secondary,
    ) -> Result<Secondary, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("UPDATE secondaries SET address = ?, enabled = ? WHERE id = ?")
            .bind(&secondary.address)
            .bind(secondary.enabled)
            .bind(secondary.id)
            .execute(&mut **sqlite_tx)
            .await?;

        Ok(secondary)
    }

    /// Delete a secondary by ID.
    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM secondaries WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
