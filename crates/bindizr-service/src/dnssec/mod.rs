//! DNSSEC zone signing: key management and rollover, the signed-view hook
//! every zone-data mutation runs before its serial bump, and the maintenance
//! scheduler. Whether a zone is signed is carried by its key rows; every
//! transition journals its delta so secondaries follow via IXFR.
//!
//! Rollover is RFC 7583 pre-publish: `published` ahead of use, `active` once
//! caches know the key (automatic for ZSKs, `ds-seen` for CSK/KSK), `retired`
//! until caches drain, then removed.

mod keys;
mod lifecycle;
mod maintenance;
mod rollover;
mod signed_view;
mod status;
#[cfg(test)]
mod tests;

use bindizr_core::{config::bindizr_config, dns::record::Rdata};
use chrono::{Duration, Utc};
pub use maintenance::init_maintenance_scheduler;

use crate::{
    database::repository::LockLevel,
    error::ServiceError,
    log_warn,
    model::{
        dnssec_key::DnssecKey,
        dnssec_record::{DnssecRecord, DnssecRecordType},
        zone::Zone,
        zone_change::{ChangeOperation, JournalRecordType, ZoneChange},
    },
    repository::{RepositoryService, RepositoryTx},
};

/// Window the per-RRset expirations spread over, so one re-signing pass does
/// not come due for every RRset at once. Small next to the refresh window.
const MAX_EXPIRATION_JITTER_SECS: u64 = 21_600;

/// Backdated inception absorbs validator clock skew; one hour covers any
/// sane offset.
const SIGNATURE_INCEPTION_OFFSET_SECS: i64 = 3600;

/// Enables, disables, rolls, and reports DNSSEC signing for zones.
pub struct DnssecService;

impl DnssecService {
    /// Recompute the zone's signed view inside the caller's mutation
    /// transaction, journaling the delta under `new_serial`. No-op for an
    /// unsigned zone. The caller holds the zone row lock and calls this after
    /// its record writes, before `advance_serial_tx`.
    pub(crate) async fn sign_zone_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        new_serial: i32,
    ) -> Result<(), ServiceError> {
        let keys = RepositoryService::list_dnssec_keys_tx(tx, zone.id, LockLevel::None).await?;
        if keys.is_empty() {
            return Ok(());
        }
        Self::sign_zone_locked(tx, zone, new_serial, &keys, false).await?;
        Ok(())
    }

    /// Returns whether anything changed; with `force`, stored signatures are
    /// ignored instead of reused.
    async fn sign_zone_locked(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        new_serial: i32,
        keys: &[DnssecKey],
        force: bool,
    ) -> Result<bool, ServiceError> {
        let records = RepositoryService::list_records_tx(tx, zone.id, LockLevel::None).await?;
        let prev = RepositoryService::list_dnssec_records_tx(tx, zone.id, LockLevel::None).await?;

        let dnssec = &bindizr_config().dnssec;
        let now = Utc::now();
        let diff = signed_view::compute_signed_view(&signed_view::SignedViewParams {
            zone,
            new_serial,
            records: &records,
            keys,
            prev: &prev,
            denial: zone.dnssec_denial,
            now,
            inception: now - Duration::seconds(SIGNATURE_INCEPTION_OFFSET_SECS),
            expiration: now + Duration::days(i64::from(dnssec.signature_validity_days)),
            expiration_jitter_secs: MAX_EXPIRATION_JITTER_SECS as i64,
            refresh_secs: i64::from(dnssec.signature_refresh_days) * 86_400,
            force,
        })?;

        if diff.is_empty() {
            return Ok(false);
        }

        // Caches can hold what this pass serves for these TTLs; retirement
        // reads the running maximum back when stamping its removal deadline.
        let data_ttl = records
            .iter()
            .map(|record| record.ttl)
            .chain([zone.default_ttl, zone.minimum_ttl])
            .max()
            .unwrap_or(zone.default_ttl);
        for key in keys {
            let signed_ttl = if key.signs_zone_data() {
                data_ttl
            } else if key.signs_key_rrsets() {
                zone.default_ttl
            } else {
                continue;
            };
            if signed_ttl > key.max_signed_ttl {
                RepositoryService::update_dnssec_key_max_signed_ttl_tx(tx, key.id, signed_ttl)
                    .await?;
            }
        }

        let changes = derived_changes(zone.id, new_serial, &diff.removed, &diff.added);
        RepositoryService::create_zone_journal_tx(tx, &changes).await?;
        let removed_ids: Vec<i32> = diff.removed.iter().map(|row| row.id).collect();
        RepositoryService::delete_dnssec_records_tx(tx, &removed_ids).await?;
        RepositoryService::create_dnssec_records_tx(tx, &diff.added).await?;
        Ok(true)
    }
}

/// Presentation form of a derived row's wire RDATA, as `dig` prints it; the
/// base64 row form when it does not parse.
pub(crate) fn rdata_presentation(record_type: DnssecRecordType, rdata: &Rdata) -> String {
    use domain::{
        base::{iana::Rtype, name::ParsedName, rdata::ParseRecordData},
        dep::octseq::parse::Parser,
        rdata::AllRecordData,
    };

    let mut parser = Parser::from_ref(rdata.as_bytes());
    AllRecordData::<_, ParsedName<_>>::parse_rdata(
        Rtype::from_int(record_type.wire_type()),
        &mut parser,
    )
    .ok()
    .flatten()
    .filter(|_| parser.remaining() == 0)
    .map(|data| data.to_string())
    .unwrap_or_else(|| rdata.to_base64())
}

/// Journal rows for a derived-plane delta: DELs for `removed`, ADDs for
/// `added`, all flagged `derived` and carrying their wire RDATA.
fn derived_changes(
    zone_id: i32,
    new_serial: i32,
    removed: &[DnssecRecord],
    added: &[DnssecRecord],
) -> Vec<ZoneChange> {
    let change = |operation: ChangeOperation, row: &DnssecRecord| ZoneChange {
        zone_id,
        serial: new_serial,
        operation,
        record_name: row.name.clone(),
        record_type: JournalRecordType::Derived(row.record_type),
        record_value: None,
        record_rdata: Some(row.rdata.clone()),
        record_ttl: row.ttl,
        record_priority: None,
        derived: true,
    };

    let mut changes = Vec::with_capacity(removed.len() + added.len());
    for row in removed {
        changes.push(change(ChangeOperation::Del, row));
    }
    for row in added {
        changes.push(change(ChangeOperation::Add, row));
    }
    changes
}

async fn notify_zone(zone_name: &str) {
    if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name)).await {
        log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
    }
}
