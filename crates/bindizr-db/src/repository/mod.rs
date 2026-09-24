//! Repository traits and their backend implementations; `tx` owns transactions.

pub(crate) mod mysql;
pub(crate) mod postgres;
pub(crate) mod sql;
pub(crate) mod sqlite;
mod tx;

use async_trait::async_trait;
use bindizr_core::dns::name::OwnerName;
use chrono::{DateTime, Utc};
pub use sql::{RecordSort, SortOrder, ZoneSort};
pub use tx::{LockLevel, RepositoryTx, begin_read_tx, begin_tx};

use super::model::{
    api_token::ApiToken,
    dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
    dnssec_policy::DnssecPolicy,
    dnssec_record::{DnssecRecord, DnssecRecordWithZone},
    record::{Record, RecordType, RecordWithZone},
    secondary::Secondary,
    token_grant::TokenGrant,
    tsig_grant::TsigGrant,
    tsig_key::TsigKey,
    zone::Zone,
    zone_change::ZoneChange,
    zone_version::ZoneVersion,
};
use crate::{DatabasePool, error::DatabaseError};

#[derive(Clone, Debug, Default)]
pub struct ZoneFilter {
    pub name: Option<String>,
    pub id: Option<i32>,
    pub mname: Option<String>,
    pub rname: Option<String>,
    pub default_ttl: Option<i32>,
    pub min_default_ttl: Option<i32>,
    pub max_default_ttl: Option<i32>,
    pub serial: Option<i32>,
    pub min_serial: Option<i32>,
    pub max_serial: Option<i32>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    /// `Some(true)` keeps the zones signing under a policy, `Some(false)`
    /// the rest.
    pub signed: Option<bool>,
    /// `Some(true)` keeps the zones the DNS plane serves, `Some(false)` the
    /// disabled ones.
    pub enabled: Option<bool>,
    pub search: Option<String>,
    /// Restrict to zones granted to this token, joined against
    /// `token_grants` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<i32>,
    pub sort: ZoneSort,
    pub order: SortOrder,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct RecordFilter {
    /// Matched through a subquery on `zones.name`, so the filter still lands
    /// on `records.zone_id` and keeps the listing on `idx_records_zone_name`
    /// while resolving the name as of the query rather than an earlier read.
    pub zone_name: Option<String>,
    pub name: Option<String>,
    pub record_type: Option<RecordType>,
    pub value: Option<String>,
    pub ttl: Option<i32>,
    pub min_ttl: Option<i32>,
    pub max_ttl: Option<i32>,
    pub priority: Option<i32>,
    pub min_priority: Option<i32>,
    pub max_priority: Option<i32>,
    pub search: Option<String>,
    /// Restrict to zones granted to this token, joined against
    /// `token_grants` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<i32>,
    pub sort: RecordSort,
    pub order: SortOrder,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

/// A derived row's rdata is wire bytes and its type a number, so only the
/// name half of a search reaches it, and value and priority not at all.
#[derive(Clone, Debug, Default)]
pub struct DnssecRecordFilter {
    /// Matched as in `RecordFilter`.
    pub zone_name: Option<String>,
    pub name: Option<String>,
    /// The wire RR type number, the column form.
    pub record_type: Option<i32>,
    pub ttl: Option<i32>,
    pub min_ttl: Option<i32>,
    pub max_ttl: Option<i32>,
    /// Partial match against the zone name, the owner name, and the FQDN —
    /// the name forms a derived row shares with a user one.
    pub search: Option<String>,
    /// Restrict to zones granted to this token, joined against
    /// `token_grants` in SQL so the bind count stays fixed; `None` is
    /// unrestricted.
    pub scope_token_id: Option<i32>,
    pub limit: Option<u32>,
    pub offset: Option<u64>,
}

#[async_trait]
pub trait ZoneRepository: Send + Sync {
    /// Insert a zone in the current transaction.
    async fn create_tx(&self, tx: &mut RepositoryTx<'_>, zone: Zone)
    -> Result<Zone, DatabaseError>;

    /// Find a zone by ID in the current transaction.
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError>;

    /// Find a zone by name.
    async fn get_by_name(&self, name: &str) -> Result<Option<Zone>, DatabaseError>;

    /// Find a zone by name in the current transaction.
    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Zone>, DatabaseError>;

    /// List all zones.
    async fn list_all(&self) -> Result<Vec<Zone>, DatabaseError>;

    /// List all zones in the current transaction.
    async fn list_all_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        lock_level: LockLevel,
    ) -> Result<Vec<Zone>, DatabaseError>;

    /// List zones matching the filter.
    async fn list_by_filter(&self, filter: ZoneFilter) -> Result<Vec<Zone>, DatabaseError>;

    /// Count zones matching the filter.
    async fn count_by_filter(&self, filter: ZoneFilter) -> Result<u64, DatabaseError>;

    /// Limit-1 probe of the zones table; health checks must stay cheap on
    /// large tables.
    async fn ping(&self) -> Result<(), DatabaseError>;

    /// Full-row update, except the DNSSEC-owned `dnssec_policy_id` and
    /// `parent_ns_addrs`: ordinary zone updates cannot clobber them.
    async fn update_tx(&self, tx: &mut RepositoryTx<'_>, zone: Zone)
    -> Result<Zone, DatabaseError>;

    /// Set only `dnssec_policy_id`, leaving the zone's other columns
    /// untouched; `None` marks the zone unsigned.
    async fn update_dnssec_policy_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        dnssec_policy_id: Option<i32>,
    ) -> Result<(), DatabaseError>;

    /// Set only `parent_ns_addrs`, leaving the zone's other columns
    /// untouched; `None` clears the configured parent servers.
    async fn update_parent_ns_addrs_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        parent_ns_addrs: Option<&str>,
    ) -> Result<(), DatabaseError>;

    /// Zones signed under the policy: the in-use check before a delete.
    async fn count_by_dnssec_policy_id(&self, dnssec_policy_id: i32) -> Result<u64, DatabaseError>;

    /// Bump only the serial, leaving the zone's other columns untouched.
    async fn update_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
    ) -> Result<(), DatabaseError>;

    /// Delete a zone by ID in the current transaction.
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError>;
}

#[async_trait]
pub trait DnssecPolicyRepository: Send + Sync {
    /// Insert a DNSSEC policy.
    async fn create(&self, policy: DnssecPolicy) -> Result<DnssecPolicy, DatabaseError>;

    /// Find a DNSSEC policy by ID in the current transaction.
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, DatabaseError>;

    /// Find a DNSSEC policy by name.
    async fn get_by_name(&self, name: &str) -> Result<Option<DnssecPolicy>, DatabaseError>;

    /// Find a DNSSEC policy by name in the current transaction.
    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<DnssecPolicy>, DatabaseError>;

    /// List all DNSSEC policies.
    async fn list_all(&self) -> Result<Vec<DnssecPolicy>, DatabaseError>;

    /// Write the editable timing fields; the
    /// key layout, algorithm, and denial mode are fixed at creation.
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        policy: DnssecPolicy,
    ) -> Result<DnssecPolicy, DatabaseError>;

    /// Delete a DNSSEC policy by ID.
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

#[async_trait]
pub trait SecondaryRepository: Send + Sync {
    /// Insert a secondary.
    async fn create(&self, secondary: Secondary) -> Result<Secondary, DatabaseError>;

    /// Find a secondary by name.
    async fn get_by_name(&self, name: &str) -> Result<Option<Secondary>, DatabaseError>;

    /// Find a secondary by name in the current transaction.
    async fn get_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        lock_level: LockLevel,
    ) -> Result<Option<Secondary>, DatabaseError>;

    /// Find a secondary by address.
    async fn get_by_address(&self, address: &str) -> Result<Option<Secondary>, DatabaseError>;

    /// List all secondaries, disabled ones included.
    async fn list_all(&self) -> Result<Vec<Secondary>, DatabaseError>;

    /// Write the address and enabled flag; the name is fixed at creation.
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        secondary: Secondary,
    ) -> Result<Secondary, DatabaseError>;

    /// Secondaries whose NOTIFY the key signs: the in-use check before a key
    /// delete.
    async fn count_by_notify_tsig_key_id(&self, tsig_key_id: i32) -> Result<u64, DatabaseError>;

    /// Delete a secondary by ID.
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

#[async_trait]
pub trait TsigKeyRepository: Send + Sync {
    /// Insert a TSIG key.
    async fn create(&self, key: TsigKey) -> Result<TsigKey, DatabaseError>;

    /// Find a TSIG key by ID.
    async fn get(&self, id: i32) -> Result<Option<TsigKey>, DatabaseError>;

    /// Find a TSIG key by name.
    async fn get_by_name(&self, name: &str) -> Result<Option<TsigKey>, DatabaseError>;

    /// List all TSIG keys.
    async fn list_all(&self) -> Result<Vec<TsigKey>, DatabaseError>;

    /// Delete a TSIG key by ID.
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

#[async_trait]
pub trait TsigGrantRepository: Send + Sync {
    /// Insert a TSIG grant.
    async fn create(&self, grant: TsigGrant) -> Result<TsigGrant, DatabaseError>;

    /// Find a TSIG grant by ID.
    async fn get(&self, id: i32) -> Result<Option<TsigGrant>, DatabaseError>;

    /// List TSIG grants for a zone.
    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<TsigGrant>, DatabaseError>;

    /// List TSIG grants for a TSIG key.
    async fn list_by_key_id(&self, tsig_key_id: i32) -> Result<Vec<TsigGrant>, DatabaseError>;

    /// Grants giving `tsig_key_id` rights in `zone_id`, for nsupdate
    /// authorization inside the update transaction.
    async fn list_by_zone_id_and_key_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        tsig_key_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<TsigGrant>, DatabaseError>;

    /// Count TSIG grants for a TSIG key.
    async fn count_by_key_id(&self, tsig_key_id: i32) -> Result<u64, DatabaseError>;

    /// Delete a TSIG grant by ID.
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;

    /// Delete every grant a TSIG key holds in one zone, returning how many
    /// rows went. One statement, so a revocation never lands half-applied.
    async fn delete_by_key_id_and_zone_id(
        &self,
        tsig_key_id: i32,
        zone_id: i32,
    ) -> Result<u64, DatabaseError>;
}

/// Persistence operations for token grants, the HTTP twin of
/// [`TsigGrantRepository`].
#[async_trait]
pub trait TokenGrantRepository: Send + Sync {
    /// Insert a token grant.
    async fn create(&self, grant: TokenGrant) -> Result<TokenGrant, DatabaseError>;

    /// Find a token grant by ID.
    async fn get(&self, id: i32) -> Result<Option<TokenGrant>, DatabaseError>;

    /// List token grants for a zone.
    async fn list_by_zone_id(&self, zone_id: i32) -> Result<Vec<TokenGrant>, DatabaseError>;

    /// Grants giving `api_token_id` rights in `zone_id`, for write
    /// authorization inside the caller's transaction.
    async fn list_by_zone_id_and_token_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        api_token_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<TokenGrant>, DatabaseError>;

    /// Every grant of `api_token_id`; drives what a scoped token can see and
    /// NOTIFY.
    async fn list_by_token_id(&self, api_token_id: i32) -> Result<Vec<TokenGrant>, DatabaseError>;

    /// Delete a token grant by ID.
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;

    /// Delete every grant a token holds in one zone, returning how many rows
    /// went. One statement, so a revocation never lands half-applied.
    async fn delete_by_token_id_and_zone_id(
        &self,
        api_token_id: i32,
        zone_id: i32,
    ) -> Result<u64, DatabaseError>;
}

#[async_trait]
pub trait RecordRepository: Send + Sync {
    /// Insert many records in one chunked statement, returning them with their
    /// assigned ids in input order.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[Record],
    ) -> Result<Vec<Record>, DatabaseError>;

    /// Find a record by ID.
    async fn get(&self, id: i32) -> Result<Option<Record>, DatabaseError>;

    /// Find a record with its zone metadata.
    async fn get_with_zone(&self, id: i32) -> Result<Option<RecordWithZone>, DatabaseError>;

    /// Find a record by ID in the current transaction.
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        lock_level: LockLevel,
    ) -> Result<Option<Record>, DatabaseError>;

    /// List records for a zone in the current transaction.
    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;

    /// List records at an owner name in a zone in the current transaction.
    async fn list_by_name_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        name: &OwnerName,
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;

    /// One owner name holding a DS record but no NS record — a delegation a DS
    /// would orphan. Row-form name, so the apex reads as the empty string.
    /// Every zone mutation runs this, so `record_type` leads the predicate to
    /// keep it on `idx_records_zone_type`.
    async fn get_ds_name_without_ns_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<String>, DatabaseError>;

    /// Load records whose owner name is any of `names` (lowercased match). Used
    /// by bulk insert to fetch only the rows that could conflict with the batch.
    async fn list_by_names_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        names: &[OwnerName],
        lock_level: LockLevel,
    ) -> Result<Vec<Record>, DatabaseError>;

    /// List matching records with their zone metadata.
    async fn list_by_filter_with_zone(
        &self,
        filter: RecordFilter,
    ) -> Result<Vec<RecordWithZone>, DatabaseError>;

    /// Count records matching the filter.
    async fn count_by_filter(&self, filter: RecordFilter) -> Result<u64, DatabaseError>;

    /// Update a record in the current transaction.
    async fn update_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        record: Record,
    ) -> Result<Record, DatabaseError>;

    /// Delete many records in as few statements as the backend's bind limit allows.
    async fn delete_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), DatabaseError>;
}

#[async_trait]
pub trait ZoneChangeRepository: Send + Sync {
    /// Insert many zone changes in one statement (chunked). Ids are not returned.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        changes: &[ZoneChange],
    ) -> Result<(), DatabaseError>;

    /// Journal rows with serial in `(from_serial, to_serial]` — the IXFR delta
    /// half-open interval: changes strictly after `from_serial`.
    async fn list_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneChange>, DatabaseError>;

    /// How many rows `list_between_serials` would return, so a caller can
    /// weigh the delta before loading it.
    async fn count_between_serials(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<u64, DatabaseError>;

    /// Read journal entries in `(from_serial, to_serial]` consistently with mutations in the
    /// current transaction.
    async fn list_between_serials_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<ZoneChange>, DatabaseError>;

    /// Prune one zone's journal rows older than `cutoff`, whole serials at a
    /// time so the remaining chain stays contiguous; requests below it fall
    /// back to AXFR. Returns the number of rows deleted.
    async fn prune_by_zone_id_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DatabaseError>;
}

#[async_trait]
pub trait ZoneVersionRepository: Send + Sync {
    /// Insert or update a zone version in the current transaction.
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        version: ZoneVersion,
    ) -> Result<ZoneVersion, DatabaseError>;

    /// Find a zone version by zone ID and serial.
    async fn get_by_serial(
        &self,
        zone_id: i32,
        serial: i32,
    ) -> Result<Option<ZoneVersion>, DatabaseError>;

    /// Versions with serial in the closed interval `[from_serial, to_serial]`;
    /// an IXFR needs both endpoint SOAs, unlike the journal's half-open range.
    async fn list_in_serial_range(
        &self,
        zone_id: i32,
        from_serial: i32,
        to_serial: i32,
    ) -> Result<Vec<ZoneVersion>, DatabaseError>;

    /// List versions for a zone, newest serial first, paginated. With
    /// `user_changes_only`, serials whose journal holds only signer-generated
    /// changes are skipped; the current serial is always listed.
    async fn list(
        &self,
        zone_id: i32,
        user_changes_only: bool,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<ZoneVersion>, DatabaseError>;

    /// Count zone versions using the requested change filter.
    async fn count(&self, zone_id: i32, user_changes_only: bool) -> Result<u64, DatabaseError>;

    /// Read a zone version by serial consistently with mutations in the current transaction.
    async fn get_by_serial_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        serial: i32,
        lock_level: LockLevel,
    ) -> Result<Option<ZoneVersion>, DatabaseError>;

    /// Prune one zone's versions older than `cutoff`, always keeping its
    /// newest (the IXFR up-to-date response reads it). Returns rows deleted.
    async fn prune_by_zone_id_older_than_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DatabaseError>;
}

#[async_trait]
pub trait DnssecKeyRepository: Send + Sync {
    /// Insert a DNSSEC key in the current transaction.
    async fn create_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        key: DnssecKey,
    ) -> Result<DnssecKey, DatabaseError>;

    /// List DNSSEC keys for a zone in the current transaction.
    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecKey>, DatabaseError>;

    /// Keys in `state` whose stamped `eligible_at` deadline has passed `cutoff`:
    /// the rollover work list.
    async fn list_by_state_eligible_before(
        &self,
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<DnssecKey>, DatabaseError>;

    /// Zone ids holding a key of `role` sitting in `state` longer than the
    /// zone's policy's ZSK lifetime (0 exempts the zone): the
    /// scheduled-rollover work list.
    async fn list_zone_ids_by_role_and_state_entered_beyond_zsk_lifetime(
        &self,
        role: DnssecKeyRole,
        state: DnssecKeyState,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<i32>, DatabaseError>;

    /// Count DNSSEC keys in the requested lifecycle state.
    async fn count_by_state(&self, state: DnssecKeyState) -> Result<u64, DatabaseError>;

    /// Update a key's lifecycle state and transition deadlines in the current transaction.
    async fn update_state_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        state: DnssecKeyState,
        changed_at: DateTime<Utc>,
        eligible_at: DateTime<Utc>,
    ) -> Result<(), DatabaseError>;

    /// Update the maximum TTL signed by a DNSSEC key in the current transaction.
    async fn update_max_signed_ttl_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        id: i32,
        max_signed_ttl: i32,
    ) -> Result<(), DatabaseError>;

    /// Delete a DNSSEC key by ID in the current transaction.
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, id: i32) -> Result<(), DatabaseError>;

    /// Delete all DNSSEC keys for a zone in the current transaction.
    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError>;
}

/// Persistence operations for the derived DNSSEC plane (the signed view).
#[async_trait]
pub trait DnssecRecordRepository: Send + Sync {
    /// Insert many derived records in one statement (chunked). Ids are not
    /// returned.
    async fn create_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        records: &[DnssecRecord],
    ) -> Result<(), DatabaseError>;

    /// List derived DNSSEC records for a zone in the current transaction.
    async fn list_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
        lock_level: LockLevel,
    ) -> Result<Vec<DnssecRecord>, DatabaseError>;

    /// Delete many derived records in as few statements as the backend's bind
    /// limit allows.
    async fn delete_many_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        ids: &[i32],
    ) -> Result<(), DatabaseError>;

    /// Delete all derived DNSSEC records for a zone in the current transaction.
    async fn delete_by_zone_id_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<(), DatabaseError>;

    /// Zones holding a signed view (any derived row): the signed-zone count.
    async fn count_zone_ids(&self) -> Result<u64, DatabaseError>;

    /// Zones holding an RRSIG that expires within their policy's re-sign
    /// window after `cutoff`: the re-sign work list.
    async fn list_zone_ids_expiring_within_refresh(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<i32>, DatabaseError>;

    /// Rows expiring within their zone's policy's re-sign window after
    /// `cutoff`; only RRSIG rows carry `expires_at`.
    async fn count_expiring_within_refresh(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DatabaseError>;

    /// Rows whose expiration has already passed `cutoff`: signatures no
    /// resolver will accept any more.
    async fn count_expired_before(&self, cutoff: DateTime<Utc>) -> Result<u64, DatabaseError>;

    /// List matching derived DNSSEC records with their zone metadata.
    async fn list_by_filter_with_zone(
        &self,
        filter: DnssecRecordFilter,
    ) -> Result<Vec<DnssecRecordWithZone>, DatabaseError>;

    /// Count derived DNSSEC records matching the filter.
    async fn count_by_filter(&self, filter: DnssecRecordFilter) -> Result<u64, DatabaseError>;
}

#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    /// Insert an API token.
    async fn create(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;

    /// Find an API token by name.
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DatabaseError>;

    /// Find an API token by its stored token hash.
    async fn get_by_token(&self, token: &str) -> Result<Option<ApiToken>, DatabaseError>;

    /// List all API tokens.
    async fn list_all(&self) -> Result<Vec<ApiToken>, DatabaseError>;

    /// Writes only the mutable columns (`description`, `expires_at`,
    /// `last_used_at`); `name`, `token`, and `is_global` are fixed at create,
    /// so callers must pass them through unchanged for the echoed row to be
    /// truthful.
    async fn update(&self, token: ApiToken) -> Result<ApiToken, DatabaseError>;

    /// Delete an API token by ID.
    async fn delete(&self, id: i32) -> Result<(), DatabaseError>;
}

/// Persistence for the per-zone DS-withdrawal flag: a row means the zone
/// publishes the RFC 8078 delete CDS/CDNSKEY pair instead of per-key ones.
#[async_trait]
pub trait DnssecWithdrawalRepository: Send + Sync {
    /// Mark a zone for DNSSEC withdrawal in the current transaction.
    async fn create_tx(&self, tx: &mut RepositoryTx<'_>, zone_id: i32)
    -> Result<(), DatabaseError>;

    /// Read a zone's DNSSEC withdrawal marker in the current transaction.
    async fn get_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<i32>, DatabaseError>;

    /// Clear a zone's DNSSEC withdrawal marker in the current transaction.
    async fn delete_tx(&self, tx: &mut RepositoryTx<'_>, zone_id: i32)
    -> Result<(), DatabaseError>;
}

#[async_trait]
pub trait CatalogZoneRepository: Send + Sync {
    /// The serial advances only when `digest` changed; returns the serial in
    /// effect after the upsert.
    async fn upsert_tx(
        &self,
        tx: &mut RepositoryTx<'_>,
        name: &str,
        digest: &str,
        base_serial: i32,
    ) -> Result<i32, DatabaseError>;
}

impl DatabasePool {
    /// The zone repository for this pool's backend.
    pub(crate) fn zone_repository(&self) -> Box<dyn ZoneRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => {
                Box::new(postgres::PostgresZoneRepository::new(postgres_pool.clone()))
            }
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteZoneRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The record repository for this pool's backend.
    pub(crate) fn record_repository(&self) -> Box<dyn RecordRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlRecordRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresRecordRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteRecordRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The DNSSEC policy repository for this pool's backend.
    pub(crate) fn dnssec_policy_repository(&self) -> Box<dyn DnssecPolicyRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnssecPolicyRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnssecPolicyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteDnssecPolicyRepository::new(sqlite_pool.clone()),
            ),
        }
    }

    /// The secondary repository for this pool's backend.
    pub(crate) fn secondary_repository(&self) -> Box<dyn SecondaryRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlSecondaryRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresSecondaryRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteSecondaryRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The TSIG key repository for this pool's backend.
    pub(crate) fn tsig_key_repository(&self) -> Box<dyn TsigKeyRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlTsigKeyRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresTsigKeyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteTsigKeyRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The TSIG grant repository for this pool's backend.
    pub(crate) fn tsig_grant_repository(&self) -> Box<dyn TsigGrantRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlTsigGrantRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresTsigGrantRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteTsigGrantRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The token grant repository for this pool's backend.
    pub(crate) fn token_grant_repository(&self) -> Box<dyn TokenGrantRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlTokenGrantRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresTokenGrantRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteTokenGrantRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The API token repository for this pool's backend.
    pub(crate) fn api_token_repository(&self) -> Box<dyn ApiTokenRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlApiTokenRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresApiTokenRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteApiTokenRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The zone change repository for this pool's backend.
    pub(crate) fn zone_change_repository(&self) -> Box<dyn ZoneChangeRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneChangeRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneChangeRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteZoneChangeRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The zone version repository for this pool's backend.
    pub(crate) fn zone_version_repository(&self) -> Box<dyn ZoneVersionRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlZoneVersionRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresZoneVersionRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteZoneVersionRepository::new(sqlite_pool.clone()),
            ),
        }
    }

    /// The catalog zone repository for this pool's backend.
    pub(crate) fn catalog_zone_repository(&self) -> Box<dyn CatalogZoneRepository> {
        match self {
            DatabasePool::MySQL(_) => Box::new(mysql::MySqlCatalogZoneRepository),
            DatabasePool::PostgreSQL(_) => Box::new(postgres::PostgresCatalogZoneRepository),
            DatabasePool::SQLite(_) => Box::new(sqlite::SqliteCatalogZoneRepository),
        }
    }

    /// The DNSSEC withdrawal repository for this pool's backend.
    pub(crate) fn dnssec_withdrawal_repository(&self) -> Box<dyn DnssecWithdrawalRepository> {
        match self {
            DatabasePool::MySQL(_) => Box::new(mysql::MySqlDnssecWithdrawalRepository),
            DatabasePool::PostgreSQL(_) => Box::new(postgres::PostgresDnssecWithdrawalRepository),
            DatabasePool::SQLite(_) => Box::new(sqlite::SqliteDnssecWithdrawalRepository),
        }
    }

    /// The DNSSEC key repository for this pool's backend.
    pub(crate) fn dnssec_key_repository(&self) -> Box<dyn DnssecKeyRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnssecKeyRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnssecKeyRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => {
                Box::new(sqlite::SqliteDnssecKeyRepository::new(sqlite_pool.clone()))
            }
        }
    }

    /// The DNSSEC record repository for this pool's backend.
    pub(crate) fn dnssec_record_repository(&self) -> Box<dyn DnssecRecordRepository> {
        match self {
            DatabasePool::MySQL(mysql_pool) => {
                Box::new(mysql::MySqlDnssecRecordRepository::new(mysql_pool.clone()))
            }
            DatabasePool::PostgreSQL(postgres_pool) => Box::new(
                postgres::PostgresDnssecRecordRepository::new(postgres_pool.clone()),
            ),
            DatabasePool::SQLite(sqlite_pool) => Box::new(
                sqlite::SqliteDnssecRecordRepository::new(sqlite_pool.clone()),
            ),
        }
    }
}
