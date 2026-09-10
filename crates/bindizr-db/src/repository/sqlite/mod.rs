mod api_token_repository_impl;
mod catalog_zone_state_repository_impl;
mod dnssec_key_repository_impl;
mod dnssec_policy_repository_impl;
mod dnssec_record_repository_impl;
mod dnssec_withdrawal_repository_impl;
mod record_repository_impl;
mod token_grant_repository_impl;
mod tsig_grant_repository_impl;
mod tsig_key_repository_impl;
mod zone_change_repository_impl;
mod zone_repository_impl;
mod zone_version_repository_impl;

pub(crate) use api_token_repository_impl::SqliteApiTokenRepository;
pub(crate) use catalog_zone_state_repository_impl::SqliteCatalogZoneStateRepository;
pub(crate) use dnssec_key_repository_impl::SqliteDnssecKeyRepository;
pub(crate) use dnssec_policy_repository_impl::SqliteDnssecPolicyRepository;
pub(crate) use dnssec_record_repository_impl::SqliteDnssecRecordRepository;
pub(crate) use dnssec_withdrawal_repository_impl::SqliteDnssecWithdrawalRepository;
pub(crate) use record_repository_impl::SqliteRecordRepository;
pub(crate) use token_grant_repository_impl::SqliteTokenGrantRepository;
pub(crate) use tsig_grant_repository_impl::SqliteTsigGrantRepository;
pub(crate) use tsig_key_repository_impl::SqliteTsigKeyRepository;
pub(crate) use zone_change_repository_impl::SqliteZoneChangeRepository;
pub(crate) use zone_repository_impl::SqliteZoneRepository;
pub(crate) use zone_version_repository_impl::SqliteZoneVersionRepository;

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use sqlx::SqlitePool;

    /// Wrapping only the bound side in `datetime()` renders the space form, so
    /// a stored `T` sorted above any cutoff of the same date.
    #[tokio::test]
    async fn a_bound_timestamp_compares_chronologically_against_a_stored_one() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE t (at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        let stored = Utc::now();
        sqlx::query("INSERT INTO t (at) VALUES (?)")
            .bind(stored)
            .execute(&pool)
            .await
            .unwrap();

        for (offset, expected) in [
            (TimeDelta::minutes(1), 1),
            (TimeDelta::days(1), 1),
            (TimeDelta::minutes(-1), 0),
            (TimeDelta::days(-1), 0),
        ] {
            let matched = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM t WHERE at < ?")
                .bind(stored + offset)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(matched, expected, "cutoff offset {}", offset);
        }
    }
}
