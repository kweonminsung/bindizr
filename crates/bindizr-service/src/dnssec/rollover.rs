//! The operator-driven half of key rollover: pre-publish a replacement, then
//! promote it once the parent DS is confirmed. ZSK promotion, which needs no
//! parent interaction, is the scheduler's.

use bindizr_core::{config::bindizr_config, dns::dnssec::generate_key};
use chrono::{Duration, Utc};

use super::{DnssecService, notify_zone, status::build_status};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    log_info,
    model::{
        dnssec_key::{DnssecKey, DnssecKeyRole, DnssecKeyState},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
    serial::generate_serial,
    types::GetDnssecStatusResponse,
    zone::ZoneService,
};

impl DnssecService {
    /// Start a key rollover: pre-publish a replacement that signs no zone
    /// data until [`Self::rollover_ds_seen`].
    pub async fn rollover_start(
        caller: &Caller,
        zone_name: &str,
        role: Option<&str>,
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

            // The replacement keeps the algorithm: an algorithm change is a
            // different, stricter procedure (RFC 6840, Section 5.11) and is not
            // supported.
            let template = keys
                .iter()
                .find(|key| key.role == target_role)
                .expect("validated above that the role exists");
            let new_key = Self::publish_replacement_key_tx(&mut tx, &zone, template).await?;

            let mut keys = keys;
            keys.push(new_key);
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

            // The parent-side wait being confirmed does not shorten the
            // zone-side one (RFC 7583, Section 3.3.1).
            let publish_wait = Duration::seconds(
                (bindizr_config().dnssec.rollover_publish_holddown_secs as i64)
                    .max(zone.default_ttl as i64),
            );
            let promotable_at = keys
                .iter()
                .filter(|key| ds_published.contains(&key.id))
                .map(|key| key.state_changed_at + publish_wait)
                .max()
                .expect("ds_published names at least one key");
            if promotable_at > Utc::now() {
                return Err(ServiceError::invalid_input(format!(
                    "the replacement key must stay published for {} seconds before it can \
                     sign, so resolvers holding the previous DNSKEY RRset can learn it; \
                     retry after {}",
                    publish_wait.num_seconds(),
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

    /// Generate and persist a pre-published replacement for `template`; the
    /// hold-down covers the served DNSKEY TTL (RFC 7583, Section 3.3.1).
    pub(crate) async fn publish_replacement_key_tx(
        tx: &mut RepositoryTx<'_>,
        zone: &Zone,
        template: &DnssecKey,
    ) -> Result<DnssecKey, ServiceError> {
        let now = Utc::now();
        let publish_wait = Duration::seconds(
            (bindizr_config().dnssec.rollover_publish_holddown_secs as i64)
                .max(zone.default_ttl as i64),
        );
        let new_key = generate_key(
            zone,
            template.algorithm,
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
                let eligible_at =
                    now + Duration::seconds(retire_wait_floor.max(key.max_signed_ttl as i64));
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
