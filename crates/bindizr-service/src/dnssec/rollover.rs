//! The operator-driven half of key rollover: pre-publish a replacement, then
//! promote it once the parent DS is confirmed. ZSK promotion, which needs no
//! parent interaction, is the scheduler's.

use bindizr_core::{
    config::bindizr_config,
    dns::{dnssec::generate_key, query::DsAnswer},
};
use chrono::{Duration, Utc};

use super::{
    DnssecService, notify_zone,
    status::{build_status, ds_info},
};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    log_info,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
    serial::generate_serial,
    types::GetDnssecStatusResponse,
    zone::ZoneService,
};

/// Floor on the post-sighting wait: a recursive resolver's answer may carry
/// a nearly drained cached TTL rather than the parent's original one.
const MIN_DS_TTL_WAIT_SECS: i64 = 3600;

impl DnssecService {
    /// Start a key rollover: pre-publish same-algorithm replacements, or —
    /// with `algorithm` — replacements for every key, double-signing the zone
    /// through the transition (RFC 6840, Section 5.11).
    pub async fn rollover_start(
        caller: &Caller,
        zone_name: &str,
        role: Option<&str>,
        algorithm: Option<&str>,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to start key rollover").await?;
        let result = async {
            let (zone, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            if keys.iter().any(|key| key.state != DnssecKeyState::Active) {
                return Err(ServiceError::dnssec_rollover_in_progress(
                    zone.name.as_str(),
                ));
            }

            let mut keys = keys;
            if let Some(name) = algorithm {
                let target = name
                    .parse::<DnssecAlgorithm>()
                    .map_err(ServiceError::invalid_input)?;
                if role.is_some() {
                    return Err(ServiceError::invalid_input(
                        "an algorithm rollover replaces every key; omit the role",
                    ));
                }
                if keys.iter().all(|key| key.algorithm == target) {
                    return Err(ServiceError::invalid_input(format!(
                        "the zone already signs with {}; roll without an algorithm to \
                         replace keys",
                        target
                    )));
                }

                // One replacement per key, so both algorithms carry a full
                // signer set through the transition.
                let templates = keys.clone();
                for template in &templates {
                    let new_key =
                        Self::publish_replacement_key_tx(&mut tx, &zone, template, target).await?;
                    keys.push(new_key);
                }
            } else {
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

                let template = keys
                    .iter()
                    .find(|key| key.role == target_role)
                    .expect("validated above that the role exists");
                let new_key =
                    Self::publish_replacement_key_tx(&mut tx, &zone, template, template.algorithm)
                        .await?;
                keys.push(new_key);
            }
            let new_serial = generate_serial(Some(zone.serial))?;
            Self::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = Self::earliest_expiry_tx(&mut tx, zone.id).await?;
            let withdrawing = RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_some();
            build_status(
                &zone,
                zone.dnssec_denial,
                &keys,
                earliest,
                new_serial,
                withdrawing,
            )
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to start key rollover").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
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
            let (zone, keys) =
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
                .filter(|key| {
                    key.state == DnssecKeyState::Published && key.role != DnssecKeyRole::Zsk
                })
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
            let keys = Self::promote_published_keys_tx(&mut tx, &zone, keys, &ds_published).await?;

            let new_serial = generate_serial(Some(zone.serial))?;
            DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = Self::earliest_expiry_tx(&mut tx, zone.id).await?;
            let withdrawing = RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_some();
            build_status(
                &zone,
                zone.dnssec_denial,
                &keys,
                earliest,
                new_serial,
                withdrawing,
            )
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await?;

        notify_zone(&response.zone_name).await;
        Ok(response)
    }

    /// Generate and persist a pre-published replacement for `template` with
    /// `algorithm`; the hold-down covers the served DNSKEY TTL (RFC 7583,
    /// Section 3.3.1).
    pub(crate) async fn publish_replacement_key_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        template: &DnssecKey,
        algorithm: DnssecAlgorithm,
    ) -> Result<DnssecKey, ServiceError> {
        let now = Utc::now();
        let publish_wait = Duration::seconds(
            (bindizr_config().dnssec.rollover_publish_holddown_secs as i64)
                .max(zone.default_ttl as i64),
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
    /// Zone names holding a pre-published SEP key: the DS poll's work list.
    pub async fn list_zone_names_with_pending_parent_ds(
        caller: &Caller,
    ) -> Result<Vec<String>, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let keys = RepositoryService::list_dnssec_keys_by_state(DnssecKeyState::Published).await?;
        let mut zone_ids: Vec<i32> = keys
            .iter()
            .filter(|key| key.role.is_sep())
            .map(|key| key.zone_id)
            .collect();
        zone_ids.sort_unstable();
        zone_ids.dedup();
        if zone_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut tx = RepositoryService::begin_read_tx("failed to list rollover zones").await?;
        let result = async {
            let mut names = Vec::with_capacity(zone_ids.len());
            for zone_id in zone_ids {
                if let Some(zone) =
                    RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::None).await?
                {
                    names.push(zone.name.as_str().to_string());
                }
            }
            Ok(names)
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to list rollover zones").await
    }

    /// Stamp first parent-DS observations for the zone's pending SEP keys and
    /// promote once every pending DS has been seen and every deadline has
    /// passed. `Ok(None)` while the rollover is not ready.
    pub async fn note_parent_ds_observed(
        caller: &Caller,
        zone_name: &str,
        seen: &[DsAnswer],
    ) -> Result<Option<GetDnssecStatusResponse>, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_tx("failed to advance key rollover").await?;
        let result = async {
            let (zone, mut keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            let now = Utc::now();

            let mut ds_published = Vec::new();
            let mut waiting = 0usize;
            for key in keys.iter_mut() {
                if key.state != DnssecKeyState::Published || key.role == DnssecKeyRole::Zsk {
                    continue;
                }
                ds_published.push(key.id);
                let ds = ds_info(&zone, key)?;
                let visible = seen.iter().find(|answer| ds.matches(answer));
                match (visible, key.ds_seen_at) {
                    (Some(answer), None) => {
                        // Resolvers may miss the DS for its TTL after it
                        // appeared, so the deadline extends by it, floored
                        // (RFC 7583).
                        let wait = i64::from(answer.ttl).max(MIN_DS_TTL_WAIT_SECS);
                        let eligible_at = key.eligible_at.max(now + Duration::seconds(wait));
                        RepositoryService::update_dnssec_key_ds_seen_tx(
                            &mut tx,
                            key.id,
                            Some(now),
                            eligible_at,
                        )
                        .await?;
                        key.ds_seen_at = Some(now);
                        key.eligible_at = eligible_at;
                        log_info!(
                            "Parent DS for zone {} key tag {} first seen; promotable at {}",
                            zone.name.as_str(),
                            key.key_tag,
                            eligible_at.format("%Y-%m-%dT%H:%M:%SZ")
                        );
                    }
                    (None, Some(_)) => {
                        // Gone again — a parent rollback, or the sighting was
                        // a stale cache; a fresh one restarts the TTL wait.
                        RepositoryService::update_dnssec_key_ds_seen_tx(
                            &mut tx,
                            key.id,
                            None,
                            key.eligible_at,
                        )
                        .await?;
                        key.ds_seen_at = None;
                        log_info!(
                            "Parent DS for zone {} key tag {} no longer visible; observation reset",
                            zone.name.as_str(),
                            key.key_tag
                        );
                    }
                    _ => {}
                }
                // Promotion needs the DS visible right now with its wait over.
                if visible.is_none() || key.ds_seen_at.is_none() || key.eligible_at > now {
                    waiting += 1;
                }
            }
            if ds_published.is_empty() || waiting > 0 {
                return Ok(None);
            }

            let keys = Self::promote_published_keys_tx(&mut tx, &zone, keys, &ds_published).await?;

            let new_serial = generate_serial(Some(zone.serial))?;
            DnssecService::sign_zone_locked(&mut tx, &zone, new_serial, &keys, false).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            let earliest = Self::earliest_expiry_tx(&mut tx, zone.id).await?;
            let withdrawing = RepositoryService::get_dnssec_withdrawal_tx(&mut tx, zone.id)
                .await?
                .is_some();
            build_status(
                &zone,
                zone.dnssec_denial,
                &keys,
                earliest,
                new_serial,
                withdrawing,
            )
            .map(Some)
        }
        .await;
        let response =
            RepositoryService::finish_tx(tx, result, "failed to advance key rollover").await?;

        if let Some(status) = &response {
            notify_zone(&status.zone_name).await;
        }
        Ok(response)
    }

    pub(crate) async fn promote_published_keys_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        keys: Vec<DnssecKey>,
        promoted: &[i32],
    ) -> Result<Vec<DnssecKey>, ServiceError> {
        let now = Utc::now();
        // The retiring key outlives the signatures it made, which resolvers
        // cache for their RRset's TTL (RFC 7583, Section 3.3.4).
        let retire_wait_floor = bindizr_config().dnssec.rollover_retire_holddown_secs as i64;
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
            .map(|key| retire_wait_floor.max(key.max_signed_ttl as i64))
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
