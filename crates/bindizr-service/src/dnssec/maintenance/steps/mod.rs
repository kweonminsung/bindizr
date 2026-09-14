//! What one maintenance step does to one zone: the transaction each scan's
//! zone ids are handed to, and the journal retention that runs beside them.

use bindizr_core::model::dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState};
use chrono::{DateTime, Duration, Utc};

use crate::{
    database::repository::LockLevel,
    dnssec::{DnssecService, rollover::promotable_sep_key_ids},
    error::ServiceError,
    log_warn,
    repository::RepositoryService,
    zone::version::ChangeSubject,
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

        let new_key =
            DnssecService::publish_replacement_key_tx(&mut tx, &zone, template, template.algorithm)
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

        // ZSKs carry no DS at the parent, so nothing outside the zone gates them.
        let keys =
            DnssecService::promote_published_keys_tx(&mut tx, &zone, keys, &due, None).await?;

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

/// Advance a zone's KSK/CSK rollover once the parent serves the new key's DS
/// — what `ds-seen` otherwise waits for an operator to assert. `None` when
/// the parent does not serve it yet or cannot be asked: waiting states, not
/// failures.
pub(crate) async fn promote_sep_keys_by_zone_id(
    zone_id: i32,
) -> Result<Option<String>, ServiceError> {
    let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
    let result = async {
        let Some((zone, policy, keys)) =
            DnssecService::find_signed_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive)
                .await?
        else {
            return Ok(None);
        };
        // The same rule `ds-seen` applies, minus the errors it reports.
        let Ok(awaiting) = promotable_sep_key_ids(&zone, &keys, false) else {
            return Ok(None);
        };
        let delegation = match DnssecService::probe_delegation(&zone, &keys).await {
            Ok(delegation) => delegation,
            Err(e) => {
                log_warn!(
                    "Parent of zone {} could not be asked for its DS, so the rollover waits: {}",
                    zone.name.as_str(),
                    e.message
                );
                return Ok(None);
            }
        };
        // Every awaiting key, like `ds-seen`: a parent still propagating the
        // change must not move the rollover on a partial answer.
        let confirmed = delegation
            .keys
            .iter()
            .filter(|key| awaiting.contains(&key.id));
        if !confirmed.clone().all(|key| key.ds_published) {
            if confirmed.clone().any(|key| key.ds_digest_unsupported) {
                log_warn!(
                    "Parent of zone {} answers only in a DS digest bindizr cannot compute, so \
                     the rollover waits",
                    zone.name.as_str()
                );
            }
            return Ok(None);
        }

        let keys = DnssecService::promote_published_keys_tx(
            &mut tx,
            &zone,
            keys,
            &awaiting,
            delegation.ds_ttl,
        )
        .await?;
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
