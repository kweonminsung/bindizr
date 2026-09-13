//! What one maintenance step does to one zone: the transaction each scan's
//! zone ids are handed to, and the journal retention that runs beside them.

use bindizr_core::model::dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState};
use chrono::{DateTime, Duration, Utc};

use crate::{
    database::repository::LockLevel, dnssec::DnssecService, error::ServiceError,
    repository::RepositoryService, zone::version::ChangeSubject,
};

/// Prune journal and version rows older than `cutoff` in one transaction: a
/// serial pruned from one table but not the other would read to IXFR clients
/// as a journal gap or a missing SOA. Returns (journal, version) rows deleted.
pub(crate) async fn prune_zone_history(cutoff: DateTime<Utc>) -> Result<(u64, u64), ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to prune zone history").await?;
    let result = async {
        let journal_rows =
            RepositoryService::prune_zone_changes_older_than_tx(&mut tx, cutoff).await?;
        let version_rows =
            RepositoryService::prune_zone_versions_older_than_tx(&mut tx, cutoff).await?;
        Ok::<_, ServiceError>((journal_rows, version_rows))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to prune zone history").await
}

/// Re-sign one zone in its own transaction, bumping the serial only when the
/// pass actually replaced signatures. `None` when there was nothing to do
/// (zone deleted or unsigned meanwhile, or a concurrent mutation re-signed it).
pub(crate) async fn sign_zone_by_zone_id(zone_id: i32) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to sign zone").await?;
    let result = async {
        let Some((zone, policy, keys)) =
            DnssecService::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive)
                .await?
        else {
            return Ok(None);
        };

        if DnssecService::resign_zone_tx(
            &mut tx,
            &zone,
            &policy,
            &keys,
            false,
            &ChangeSubject::system(),
        )
        .await?
        .is_none()
        {
            return Ok(None);
        }
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to sign zone").await
}

/// Pre-publish a replacement for a zone's lifetime-expired ZSK in its own
/// transaction. `None` when the state moved on concurrently.
pub(crate) async fn start_zsk_rollover_by_zone_id(
    zone_id: i32,
) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to start key rollover").await?;
    let result = async {
        let Some((zone, policy, keys)) =
            DnssecService::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive)
                .await?
        else {
            return Ok(None);
        };
        if policy.zsk_lifetime_days <= 0 {
            return Ok(None);
        }
        let cutoff = Utc::now() - Duration::days(i64::from(policy.zsk_lifetime_days));
        if keys.iter().any(|key| key.state != DnssecKeyState::Active) {
            return Ok(None);
        }
        let Some(template) = keys
            .iter()
            .find(|key| key.role == DnssecKeyRole::Zsk && key.state_changed_at < cutoff)
        else {
            return Ok(None);
        };

        let new_key = DnssecService::publish_replacement_key_tx(
            &mut tx,
            &zone,
            &policy,
            template,
            template.algorithm,
        )
        .await?;
        let mut keys = keys;
        keys.push(new_key);
        DnssecService::resign_zone_tx(
            &mut tx,
            &zone,
            &policy,
            &keys,
            false,
            &ChangeSubject::system(),
        )
        .await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to start key rollover").await
}

/// Promote a zone's hold-down-expired pre-published ZSKs in its own
/// transaction. `None` when the state moved on concurrently.
pub(crate) async fn promote_zsks_by_zone_id(zone_id: i32) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
    let result = async {
        let Some((zone, policy, keys)) =
            DnssecService::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive)
                .await?
        else {
            return Ok(None);
        };

        let now = Utc::now();
        let due: Vec<i32> = keys
            .iter()
            .filter(|key| {
                key.role == DnssecKeyRole::Zsk
                    && key.state == DnssecKeyState::Published
                    && key.eligible_at <= now
            })
            .map(|key| key.id)
            .collect();
        if due.is_empty() {
            return Ok(None);
        }

        let keys =
            DnssecService::promote_published_keys_tx(&mut tx, &zone, &policy, keys, &due).await?;

        DnssecService::resign_zone_tx(
            &mut tx,
            &zone,
            &policy,
            &keys,
            false,
            &ChangeSubject::system(),
        )
        .await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await
}

/// The retired keys past their hold-down that the zone can afford to drop:
/// either another key of that algorithm still signs zone data, or the whole
/// algorithm is leaving at once (RFC 6840, Section 5.11 keeps an algorithm's
/// DNSKEYs and its signatures together).
pub(crate) fn removable_key_ids(keys: &[DnssecKey], now: DateTime<Utc>) -> Vec<i32> {
    keys.iter()
        .filter(|key| {
            if key.state != DnssecKeyState::Retired || key.eligible_at > now {
                return false;
            }

            let another_key_signs_data = keys.iter().any(|other| {
                matches!(other.role, DnssecKeyRole::Csk | DnssecKeyRole::Zsk)
                    && other.state == DnssecKeyState::Active
                    && other.algorithm == key.algorithm
            });

            another_key_signs_data
                || keys
                    .iter()
                    .filter(|other| other.algorithm == key.algorithm)
                    .all(|other| other.state == DnssecKeyState::Retired && other.eligible_at <= now)
        })
        .map(|key| key.id)
        .collect()
}

/// Remove a zone's hold-down-expired retired keys in its own transaction.
/// `None` when nothing was removable, or when removing would leave no key.
pub(crate) async fn remove_retired_keys_by_zone_id(
    zone_id: i32,
) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to remove retired keys").await?;
    let result = async {
        let Some((zone, policy, keys)) =
            DnssecService::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive)
                .await?
        else {
            return Ok(None);
        };

        let removable = removable_key_ids(&keys, Utc::now());
        // Decided before any row goes: taking every key would leave the signed
        // records with no DNSKEY to validate them.
        if removable.is_empty() || removable.len() == keys.len() {
            return Ok(None);
        }

        let mut remaining = Vec::with_capacity(keys.len());
        for key in keys {
            if removable.contains(&key.id) {
                RepositoryService::delete_dnssec_key_tx(&mut tx, key.id).await?;
            } else {
                remaining.push(key);
            }
        }

        DnssecService::resign_zone_tx(
            &mut tx,
            &zone,
            &policy,
            &remaining,
            false,
            &ChangeSubject::system(),
        )
        .await?;
        Ok(Some(zone.name.as_str().to_string()))
    }
    .await;
    RepositoryService::finish_tx(tx, result, "failed to remove retired keys").await
}

#[cfg(test)]
mod tests;
