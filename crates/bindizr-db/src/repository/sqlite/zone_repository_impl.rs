use async_trait::async_trait;
use sqlx::{Pool, Sqlite};

use crate::{
    error::DatabaseError,
    model::zone::{DnssecDenial, Zone},
    repository::{LockLevel, RepositoryTx, ZoneFilter, ZoneRepository, sql::like_pattern},
};

/// SQLite-backed implementation of `ZoneRepository`.
pub(crate) struct SqliteZoneRepository {
    pool: Pool<Sqlite>,
}

impl SqliteZoneRepository {
    pub(crate) fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ZoneRepository for SqliteZoneRepository {
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        mut zone: Zone,
    ) -> Result<Zone, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let result = sqlx::query(
            r#"
            INSERT INTO zones (name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .execute(&mut **sqlite_tx)
        .await?;

        zone.id = result.last_insert_rowid() as i32;
        Ok(zone)
    }

    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        _lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_denial, created_at FROM zones WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut **sqlite_tx)
            .await?;

        Ok(zone)
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_denial, created_at FROM zones WHERE name = ?")
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(zone)
    }

    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        _lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let zone = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_denial, created_at FROM zones WHERE name = ?")
            .bind(name)
            .fetch_optional(&mut **sqlite_tx)
            .await?;

        Ok(zone)
    }

    async fn list_all(&self) -> Result<Vec<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;

        let zones = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_denial, created_at FROM zones ORDER BY name")
            .fetch_all(&mut *conn)
            .await?;

        Ok(zones)
    }

    async fn list_all_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        _lock_level: LockLevel,
    ) -> Result<Vec<Zone>, DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        let zones = sqlx::query_as::<_, Zone>("SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_denial, created_at FROM zones ORDER BY name")
            .fetch_all(&mut **sqlite_tx)
            .await?;

        Ok(zones)
    }

    async fn list_by_filter(&self, filter: ZoneFilter) -> Result<Vec<Zone>, DatabaseError> {
        let mut conn = self.pool.acquire().await?;
        let search = like_pattern(filter.search.as_deref());

        let zones = sqlx::query_as::<_, Zone>(
            r#"
            SELECT id, name, mname, rname, default_ttl, serial, refresh, retry, expire, minimum_ttl, dnssec_denial, created_at
            FROM zones
            WHERE (? IS NULL OR LOWER(name) = LOWER(?))
              AND (? IS NULL OR id = ?)
              AND (? IS NULL OR LOWER(mname) = LOWER(?))
              AND (? IS NULL OR LOWER(rname) = LOWER(?))
              AND (? IS NULL OR default_ttl = ?)
              AND (? IS NULL OR default_ttl >= ?)
              AND (? IS NULL OR default_ttl <= ?)
              AND (? IS NULL OR serial = ?)
              AND (
                    ? IS NULL
                    OR LOWER(name) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(mname) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(rname) LIKE LOWER(?) ESCAPE '\'
              )
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = ? AND p.zone_id = zones.id)
              )
            ORDER BY name
            LIMIT ? OFFSET ?
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
        .bind(filter.scope_token_id)
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
            WHERE (? IS NULL OR LOWER(name) = LOWER(?))
              AND (? IS NULL OR id = ?)
              AND (? IS NULL OR LOWER(mname) = LOWER(?))
              AND (? IS NULL OR LOWER(rname) = LOWER(?))
              AND (? IS NULL OR default_ttl = ?)
              AND (? IS NULL OR default_ttl >= ?)
              AND (? IS NULL OR default_ttl <= ?)
              AND (? IS NULL OR serial = ?)
              AND (
                    ? IS NULL
                    OR LOWER(name) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(mname) LIKE LOWER(?) ESCAPE '\'
                    OR LOWER(rname) LIKE LOWER(?) ESCAPE '\'
              )
              AND (
                    ? IS NULL
                    OR EXISTS (SELECT 1 FROM zone_token_policies p
                               WHERE p.api_token_id = ? AND p.zone_id = zones.id)
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
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query(
            r#"
            UPDATE zones 
            SET name = ?, mname = ?, rname = ?,
                default_ttl = ?, serial = ?, refresh = ?, retry = ?, expire = ?, minimum_ttl = ?
            WHERE id = ?
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
        .execute(&mut **sqlite_tx)
        .await?;

        Ok(zone)
    }

    async fn update_dnssec_denial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        denial: DnssecDenial,
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("UPDATE zones SET dnssec_denial = ? WHERE id = ?")
            .bind(denial.as_str())
            .bind(zone_id)
            .execute(&mut **sqlite_tx)
            .await?;

        Ok(())
    }

    async fn update_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("UPDATE zones SET serial = ? WHERE id = ?")
            .bind(serial)
            .bind(zone_id)
            .execute(&mut **sqlite_tx)
            .await?;
        Ok(())
    }

    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError> {
        let sqlite_tx = tx.as_sqlite()?;

        sqlx::query("DELETE FROM zones WHERE id = ?")
            .bind(id)
            .execute(&mut **sqlite_tx)
            .await?;
        Ok(())
    }
}
