use crate::database::error::DatabaseError;
use crate::database::{
    model::zone_snapshot::ZoneSnapshot,
    repository::{RepositoryTx, RepositoryTxKind, ZoneSnapshotRepository},
};
use async_trait::async_trait;
use sqlx::{MySql, Pool};

pub struct MySqlZoneSnapshotRepository {
    pool: Pool<MySql>,
}

impl MySqlZoneSnapshotRepository {
    pub fn new(pool: Pool<MySql>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneSnapshotRepository for MySqlZoneSnapshotRepository {
    async fn upsert(&self, snapshot: ZoneSnapshot) -> Result<ZoneSnapshot, DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO zone_soa_history (zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                primary_ns = VALUES(primary_ns),
                admin_email = VALUES(admin_email),
                ttl = VALUES(ttl),
                refresh = VALUES(refresh),
                retry = VALUES(retry),
                expire = VALUES(expire),
                minimum_ttl = VALUES(minimum_ttl)
            "#,
        )
        .bind(snapshot.zone_id)
        .bind(snapshot.serial)
        .bind(&snapshot.primary_ns)
        .bind(&snapshot.admin_email)
        .bind(snapshot.ttl)
        .bind(snapshot.refresh)
        .bind(snapshot.retry)
        .bind(snapshot.expire)
        .bind(snapshot.minimum_ttl)
        .execute(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = ? AND serial = ?
            "#,
        )
        .bind(snapshot.zone_id)
        .bind(snapshot.serial)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        snapshot: ZoneSnapshot,
    ) -> Result<ZoneSnapshot, DatabaseError> {
        let mysql_tx = match &mut tx.0 {
            RepositoryTxKind::MySQL(tx) => tx,
            _ => {
                return Err(DatabaseError::TransactionFailed(
                    "transaction kind mismatch (expected MySQL)".to_string(),
                ));
            }
        };

        sqlx::query(
            r#"
            INSERT INTO zone_soa_history (zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                primary_ns = VALUES(primary_ns),
                admin_email = VALUES(admin_email),
                ttl = VALUES(ttl),
                refresh = VALUES(refresh),
                retry = VALUES(retry),
                expire = VALUES(expire),
                minimum_ttl = VALUES(minimum_ttl)
            "#,
        )
        .bind(snapshot.zone_id)
        .bind(snapshot.serial)
        .bind(&snapshot.primary_ns)
        .bind(&snapshot.admin_email)
        .bind(snapshot.ttl)
        .bind(snapshot.refresh)
        .bind(snapshot.retry)
        .bind(snapshot.expire)
        .bind(snapshot.minimum_ttl)
        .execute(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;

        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = ? AND serial = ?
            "#,
        )
        .bind(snapshot.zone_id)
        .bind(snapshot.serial)
        .fetch_one(&mut **mysql_tx)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }

    async fn get_by_zone_id_and_serial(
        &self,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneSnapshot>, DatabaseError> {
        sqlx::query_as::<_, ZoneSnapshot>(
            r#"
            SELECT id, zone_id, serial, primary_ns, admin_email, ttl, refresh, retry, expire, minimum_ttl, created_at
            FROM zone_soa_history
            WHERE zone_id = ? AND serial = ?
            "#,
        )
        .bind(zone_id)
        .bind(serial)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DatabaseError::QueryFailed(e.to_string()))
    }
}
