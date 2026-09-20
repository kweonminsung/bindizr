//! The operator-driven half of key rollover: pre-publish a replacement, then
//! promote it once the parent DS is confirmed. ZSK promotion, which needs no
//! parent interaction, is the scheduler's.

use bindizr_core::dns::dnssec::generate_key;
use chrono::{Duration, Utc};

use super::{DnssecService, notify_zone, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_policy::DnssecPolicy,
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
    types::{DnssecDelegationKeyInfo, GetDnssecStatusResponse},
};

impl DnssecService {
    /// Start a key rollover: pre-publish a same-algorithm replacement for
    /// the CSK, or for the `role` named in a split-key zone.
    pub async fn start_rollover(
        caller: &Caller,
        zone_name: &str,
        role: Option<&str>,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to start key rollover").await?;
        let result = async {
            // Select a role only after ruling out an existing rollover under the zone lock.
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if keys.iter().any(|key| key.state != DnssecKeyState::Active) {
                return Err(ServiceError::dnssec_rollover_in_progress(
                    zone.name.as_str(),
                ));
            }

            let target_role = match role {
                Some(name) => {
                    let parsed = name
                        .parse::<DnssecKeyRole>()
                        .map_err(ServiceError::invalid_input)?;
                    if !keys.iter().any(|key| key.role == parsed) {
                        return Err(ServiceError::invalid_input(format!(
                            "zone '{}' has no {} key to roll",
                            zone.name, parsed
                        )));
                    }
                    parsed
                }
                None => {
                    if keys.iter().all(|key| key.role == DnssecKeyRole::Csk) {
                        DnssecKeyRole::Csk
                    } else {
                        return Err(ServiceError::invalid_input(
                            "this zone uses split keys; pass the role to roll (ksk or zsk)",
                        ));
                    }
                }
            };

            // Publish the replacement alongside the active keys; promotion waits
            // for the role's hold-down and, for a SEP key, the parent DS check.
            let mut keys = keys;
            let template = keys
                .iter()
                .find(|key| key.role == target_role)
                .expect("validated above that the role exists");
            let new_key =
                Self::publish_replacement_key_tx(&mut tx, &zone, template, template.algorithm)
                    .await?;
            keys.push(new_key);

            let new_serial = Self::resign_zone_tx(
                &mut tx,
                &zone,
                &policy,
                &keys,
                false,
                &caller.change_subject(),
            )
            .await?
            .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to start key rollover").await?;

        log::info!("event=dnssec_rollover_start zone={}", response.zone_name);

        // Announce the pre-published key after the signed view commits.
        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Pre-publish a replacement for every key with `policy`'s algorithm,
    /// double-signing the zone through the transition (RFC 6840, Section
    /// 5.11). Returns the key set with the replacements appended.
    pub(crate) async fn start_algorithm_rollover_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        policy: &DnssecPolicy,
        keys: Vec<DnssecKey>,
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        if keys.iter().any(|key| key.state != DnssecKeyState::Active) {
            return Err(ServiceError::dnssec_rollover_in_progress(
                zone.name.as_str(),
            ));
        }

        // One replacement per key, so both algorithms carry a full signer
        // set through the transition.
        let mut keys = keys;
        let templates = keys.clone();
        for template in &templates {
            let new_key =
                Self::publish_replacement_key_tx(tx, zone, template, policy.algorithm).await?;
            keys.push(new_key);
        }
        Ok(keys)
    }

    /// Promote the pre-published SEP key(s) and retire the keys they replace
    /// once the parent serves their DS and the hold-down has passed;
    /// `skip_ds_check` takes the DS on the operator's word, `skip_holddown`
    /// waives the wait.
    pub async fn advance_rollover(
        caller: &Caller,
        zone_name: &str,
        skip_ds_check: bool,
        skip_holddown: bool,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let awaiting = promotable_sep_key_ids(&zone, &keys, skip_holddown)?;
            // The answer that confirms the DS also says how long resolvers
            // cache it — the wait the key it replaces must outlive.
            let mut parent_ds_ttl = None;
            if !skip_ds_check {
                let delegation = Self::probe_delegation(&zone, &keys).await?;
                parent_ds_ttl = delegation.ds_ttl;
                let unconfirmed: Vec<&DnssecDelegationKeyInfo> = delegation
                    .keys
                    .iter()
                    .filter(|key| awaiting.contains(&key.id) && !key.ds_published)
                    .collect();
                let unsupported: Vec<u16> = unconfirmed
                    .iter()
                    .filter(|key| key.ds_digest_unsupported)
                    .map(|key| key.key_tag)
                    .collect();
                if !unsupported.is_empty() {
                    return Err(ServiceError::dnssec_ds_digest_unsupported(
                        zone.name.as_str(),
                        &unsupported,
                    ));
                }
                let missing: Vec<u16> = unconfirmed.iter().map(|key| key.key_tag).collect();
                if !missing.is_empty() {
                    return Err(ServiceError::dnssec_ds_not_published(
                        zone.name.as_str(),
                        &missing,
                    ));
                }
            }
            let keys =
                Self::promote_published_keys_tx(&mut tx, &zone, keys, &awaiting, parent_ds_ttl)
                    .await?;

            let new_serial = DnssecService::resign_zone_tx(
                &mut tx,
                &zone,
                &policy,
                &keys,
                false,
                &caller.change_subject(),
            )
            .await?
            .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await?;

        if skip_ds_check {
            log::warn!(
                "event=dnssec_rollover_ds_seen_ds_check_skipped zone={}",
                response.zone_name
            );
        }
        if skip_holddown {
            log::warn!(
                "event=dnssec_rollover_ds_seen_holddown_skipped zone={}",
                response.zone_name
            );
        }
        log::info!("event=dnssec_rollover_ds_seen zone={}", response.zone_name);
        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Publish a replacement for `template` with `algorithm`. Promotion waits
    /// for the DNSKEY TTL; algorithm rollovers may require signing before then.
    pub(crate) async fn publish_replacement_key_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        template: &DnssecKey,
        algorithm: DnssecAlgorithm,
    ) -> Result<DnssecKey, ServiceError> {
        let now = Utc::now();
        let publish_wait = Duration::seconds(i64::from(zone.default_ttl));
        let new_key = generate_key(
            zone,
            algorithm,
            template.role,
            DnssecKeyState::Published,
            now,
            now + publish_wait,
        )
        .map_err(ServiceError::dnssec_signing_failed)?;
        RepositoryService::create_dnssec_key_tx(tx, new_key).await
    }

    /// Promote the published keys named by `promoted` — drawn from this
    /// transaction's key list — and retire the active keys of the same roles.
    pub(crate) async fn promote_published_keys_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        keys: Vec<DnssecKey>,
        promoted: &[i32],
        parent_ds_ttl: Option<u32>,
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        let now = Utc::now();
        let promoted_roles: Vec<DnssecKeyRole> = keys
            .iter()
            .filter(|key| promoted.contains(&key.id))
            .map(|key| key.role)
            .collect();
        // One deadline for the whole retiring batch: an algorithm rollover
        // must drop the old DNSKEYs and their signatures together.
        let retire_wait = keys
            .iter()
            .filter(|key| key.state == DnssecKeyState::Active && promoted_roles.contains(&key.role))
            .map(|key| key.retirement_interval_secs(parent_ds_ttl))
            .max()
            .unwrap_or(0);

        let mut updated = Vec::with_capacity(keys.len());
        for mut key in keys {
            if promoted.contains(&key.id) {
                RepositoryService::update_dnssec_key_state_tx(
                    tx,
                    key.id,
                    DnssecKeyState::Active,
                    now,
                    now,
                )
                .await?;
                key.state = DnssecKeyState::Active;
                key.state_changed_at = now;
                key.eligible_at = now;
            } else if key.state == DnssecKeyState::Active && promoted_roles.contains(&key.role) {
                let eligible_at = now + Duration::seconds(retire_wait);
                RepositoryService::update_dnssec_key_state_tx(
                    tx,
                    key.id,
                    DnssecKeyState::Retired,
                    now,
                    eligible_at,
                )
                .await?;
                key.state = DnssecKeyState::Retired;
                key.state_changed_at = now;
                key.eligible_at = eligible_at;
            }
            updated.push(key);
        }

        log::info!(
            "Promoted {} pre-published DNSSEC key(s) for zone {}",
            promoted.len(),
            zone.name
        );
        Ok(updated)
    }
}

/// The pre-published SEP keys a promotion may take; an error when no
/// rollover is in progress, it replaces only the ZSK, or (unless
/// `skip_holddown`) a wait runs. `ds-seen` reports those errors; the
/// scheduler reads them as nothing to do.
pub(crate) fn promotable_sep_key_ids(
    zone: &Zone,
    keys: &[DnssecKey],
    skip_holddown: bool,
) -> Result<Vec<i32>, ServiceError> {
    if !keys
        .iter()
        .any(|key| key.state == DnssecKeyState::Published)
    {
        return Err(ServiceError::dnssec_no_rollover_in_progress(
            zone.name.as_str(),
        ));
    }
    // ZSKs have no parent DS to confirm; their own step promotes them.
    let ds_published: Vec<i32> = keys
        .iter()
        .filter(|key| key.awaits_parent_ds())
        .map(|key| key.id)
        .collect();
    if ds_published.is_empty() {
        return Err(ServiceError::invalid_input(
            "this rollover replaces the ZSK, which involves no parent DS; it is promoted \
             automatically after the publish hold-down",
        ));
    }

    // The deadline stamped at publication is authoritative: a later TTL
    // change cannot shorten it (status reports it).
    let promotable_at = keys
        .iter()
        .filter(|key| ds_published.contains(&key.id))
        .map(|key| key.eligible_at)
        .max()
        .expect("ds_published names at least one key");
    if !skip_holddown && promotable_at > Utc::now() {
        return Err(ServiceError::invalid_input(format!(
            "the replacement key must stay published so resolvers holding the previous \
             DNSKEY records can learn it; retry after {}, or skip the hold-down and accept \
             validation failures until those caches expire",
            promotable_at.format("%Y-%m-%dT%H:%M:%SZ"),
        )));
    }
    Ok(ds_published)
}

#[cfg(test)]
mod tests;
