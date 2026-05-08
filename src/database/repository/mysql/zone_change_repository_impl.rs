use crate::database::error::DatabaseError;
use crate::database::{
    model::zone_change::ZoneChange,
    repository::{RepositoryTx, RepositoryTxKind, ZoneChangeRepository},
};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlZoneChangeRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneChangeRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneChangeRepository for MySqlZoneChangeRepository {
    async fn create(&self, zone_change: ZoneChange) -> Result<ZoneChange, DatabaseError> {
        let result = sqlx::query(
            r#"
            INSERT INTO zone_changes (zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(zone_change.zone_id)
        .bind(zone_change.serial)
        .bind(&zone_change.operation)
        .bind(&zone_change.record_name)
        .bind(&zone_change.record_type)
        .bind(&zone_change.record_value)
        .bind(zone_change.record_ttl)
        .bind(zone_change.record_priority)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        let id = result.last_insert_id() as i32;

        sqlx::query_as::<_, ZoneChange>(
            r#"
            SELECT id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            FROM zone_changes
            WHERE id = ?
            "#
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_change: ZoneChange,
    ) -> Result<ZoneChange, DatabaseError> {
        let mysql_tx = match &mut tx.0 {
            RepositoryTxKind::MySQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected MySQL)".to_string(),
                ));
            }
        };

        let result = sqlx::query(
            r#"
            INSERT INTO zone_changes (zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(zone_change.zone_id)
        .bind(zone_change.serial)
        .bind(&zone_change.operation)
        .bind(&zone_change.record_name)
        .bind(&zone_change.record_type)
        .bind(&zone_change.record_value)
        .bind(zone_change.record_ttl)
        .bind(zone_change.record_priority)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        let id = result.last_insert_id() as i32;

        sqlx::query_as::<_, ZoneChange>(
            r#"
            SELECT id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            FROM zone_changes
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn get_changes_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError> {
        sqlx::query_as::<_, ZoneChange>(
            r#"
            SELECT id, zone_id, serial, operation, record_name, record_type, record_value, record_ttl, record_priority
            FROM zone_changes
            WHERE zone_id = ? AND serial > ? AND serial <= ?
            ORDER BY serial, id
            "#
        )
        .bind(zone_id)
        .bind(from_serial)
        .bind(to_serial)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
