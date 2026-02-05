use crate::database::error::DatabaseError;
use crate::database::{model::key::Key, repository::KeyRepository};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

pub struct SqliteKeyRepository {
    pool: Pool<Sqlite>,
}

impl SqliteKeyRepository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyRepository for SqliteKeyRepository {
    async fn create(&self, mut key: Key) -> Result<Key, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO keys (name, key_type, key_algorithm, secret)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(&key.name)
        .bind(key.key_type.as_str())
        .bind(key.key_algorithm.as_str())
        .bind(&key.secret)
        .execute(&mut *conn)
        .await?;

        key.id = result.last_insert_rowid() as i32;

        Ok(key)
    }

    async fn get_by_id(&self, id: i32) -> Result<Option<Key>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let key = sqlx::query_as::<_, Key>(
            "SELECT id, name, key_type, key_algorithm, secret, created_at FROM keys WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(key)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Key>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let key = sqlx::query_as::<_, Key>(
            "SELECT id, name, key_type, key_algorithm, secret, created_at FROM keys WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(key)
    }

    async fn get_all(&self) -> Result<Vec<Key>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let keys = sqlx::query_as::<_, Key>(
            "SELECT id, name, key_type, key_algorithm, secret, created_at FROM keys ORDER BY id",
        )
        .fetch_all(&mut *conn)
        .await?;

        Ok(keys)
    }

    async fn update(&self, key: Key) -> Result<Key, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            UPDATE keys 
            SET name = ?, key_type = ?, key_algorithm = ?, secret = ?
            WHERE id = ?
            "#,
        )
        .bind(&key.name)
        .bind(key.key_type.as_str())
        .bind(key.key_algorithm.as_str())
        .bind(&key.secret)
        .bind(key.id)
        .execute(&mut *conn)
        .await?;

        Ok(key)
    }

    async fn delete(&self, id: i32) -> Result<(), DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        sqlx::query("DELETE FROM keys WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}
