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
    log_info,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_policy::DnssecPolicy,
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
    types::GetDnssecStatusResponse,
};

impl DnssecService {
    /// Start a key rollover: pre-publish a same-algorithm replacement for
    /// the CSK, or for the `role` named in a split-key zone.
    pub async fn rollover_start(
        caller: &Caller,
        zone_name: &str,
        role: Option<&str>,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to start key rollover").await?;
        let result = async {
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

            let mut keys = keys;
            let template = keys
                .iter()
                .find(|key| key.role == target_role)
                .expect("validated above that the role exists");
            let new_key = Self::publish_replacement_key_tx(
                &mut tx,
                &zone,
                &policy,
                template,
                template.algorithm,
            )
            .await?;
            keys.push(new_key);

            let new_serial = Self::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to start key rollover").await?;

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
                Self::publish_replacement_key_tx(tx, zone, policy, template, policy.algorithm)
                    .await?;
            keys.push(new_key);
        }
        Ok(keys)
    }

    /// The operator's confirmation that the new DS is at the parent and its
    /// TTL has passed: promotes the pre-published key(s) and retires the keys
    /// they replace. ZSK rollovers are promoted by the scheduler instead.
    pub async fn rollover_ds_seen(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;

            if !keys
                .iter()
                .any(|key| key.state == DnssecKeyState::Published)
            {
                return Err(ServiceError::dnssec_no_rollover_in_progress(
                    zone.name.as_str(),
                ));
            }
            // ZSKs have no parent DS to confirm; the scheduler promotes them
            // after the publish hold-down.
            let ds_published: Vec<i32> = keys
                .iter()
                .filter(|key| key.awaits_parent_ds())
                .map(|key| key.id)
                .collect();
            if ds_published.is_empty() {
                return Err(ServiceError::invalid_input(
                    "this rollover replaces the ZSK, which involves no parent DS; it is \
                     promoted automatically after the publish hold-down",
                ));
            }

            // The deadline stamped at publication is authoritative: later
            // hold-down or TTL changes cannot shorten it (status reports it).
            let promotable_at = keys
                .iter()
                .filter(|key| ds_published.contains(&key.id))
                .map(|key| key.eligible_at)
                .max()
                .expect("ds_published names at least one key");
            if promotable_at > Utc::now() {
                return Err(ServiceError::invalid_input(format!(
                    "the replacement key must stay published so resolvers holding the \
                     previous DNSKEY RRset can learn it; retry after {}",
                    promotable_at.format("%Y-%m-%dT%H:%M:%SZ"),
                )));
            }
            let keys =
                Self::promote_published_keys_tx(&mut tx, &zone, &policy, keys, &ds_published)
                    .await?;

            let new_serial = DnssecService::resign_zone_tx(&mut tx, &zone, &policy, &keys, false)
                .await?
                .unwrap_or(zone.serial);

            build_status_tx(&mut tx, &zone, Some(&policy), &keys, new_serial).await
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Generate and persist a pre-published replacement for `template` with
    /// `algorithm`; the policy's hold-down covers the served DNSKEY TTL (RFC
    /// 7583, Section 3.3.1).
    pub(crate) async fn publish_replacement_key_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        policy: &DnssecPolicy,
        template: &DnssecKey,
        algorithm: DnssecAlgorithm,
    ) -> Result<DnssecKey, ServiceError> {
        let now = Utc::now();
        let publish_wait = Duration::seconds(
            policy
                .rollover_publish_holddown_secs
                .max(i64::from(zone.default_ttl)),
        );
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
        policy: &DnssecPolicy,
        keys: Vec<DnssecKey>,
        promoted: &[i32],
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        let now = Utc::now();
        // The retiring key outlives the signatures it made, which resolvers
        // cache for their RRset's TTL (RFC 7583, Section 3.3.4).
        let retire_wait_floor = policy.rollover_retire_holddown_secs;
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
            .map(|key| retire_wait_floor.max(i64::from(key.max_signed_ttl)))
            .max()
            .unwrap_or(retire_wait_floor);

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

        log_info!(
            "Promoted {} pre-published DNSSEC key(s) for zone {}",
            promoted.len(),
            zone.name
        );
        Ok(updated)
    }
}
