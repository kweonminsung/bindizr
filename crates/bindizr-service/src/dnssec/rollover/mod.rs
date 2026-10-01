//! The operator-driven half of key rollover: pre-publish a replacement, then
//! promote it once the parent DS is confirmed. ZSK promotion, which needs no
//! parent interaction, is the scheduler's.

use bindizr_core::{
    dns::{
        dnssec::{KeyTag, SigningPass},
        name::ZoneName,
    },
    model::dnssec_key::DnssecKeyId,
};
use bindizr_db::LockLevel;
use chrono::{Duration, Utc};

use super::status::build_status_tx;
use crate::{
    Context, Transaction,
    authorization::Caller,
    dnssec::SignedZone,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        dnssec_policy::DnssecPolicy,
        zone::Zone,
    },
    transaction,
    types::{
        DnssecDelegationKeyInfo, DnssecStatusResponse, DsCheck, Holddown, RolloverDnssecRequest,
    },
};

/// Start a key rollover: pre-publish a same-algorithm replacement for
/// the CSK, or for the `role` named in a split-key zone.
pub async fn start_rollover(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    request: &RolloverDnssecRequest,
) -> Result<DnssecStatusResponse, ServiceError> {
    caller.authorize_global("manage DNSSEC signing")?;
    let role = request
        .role
        .as_deref()
        .map(str::parse::<DnssecKeyRole>)
        .transpose()
        .map_err(ServiceError::invalid_input)?;

    let mut tx = transaction::begin_tx(cx, "failed to start key rollover").await?;
    let result = async {
        // Select a role only after ruling out an existing rollover under the zone lock.
        let mut signed =
            super::lookup_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        if signed
            .keys
            .iter()
            .any(|key| key.state != DnssecKeyState::Active)
        {
            return Err(ServiceError::dnssec_rollover_in_progress(
                signed.zone.name.as_str(),
            ));
        }

        // The key the replacement is modelled on: one of the requested role,
        // or the CSK when the zone has no other kind.
        let template = match role {
            Some(role) => signed.keys.iter().find(|key| key.role == role),
            None if signed.keys.iter().all(|key| key.role == DnssecKeyRole::Csk) => {
                signed.keys.first()
            }
            None => {
                return Err(ServiceError::invalid_input(
                    "this zone uses split keys; pass the role to roll (ksk or zsk)",
                ));
            }
        };
        let Some(template) = template else {
            return Err(ServiceError::invalid_input(format!(
                "zone '{}' has no {} key to roll",
                signed.zone.name,
                role.unwrap_or(DnssecKeyRole::Csk)
            )));
        };

        // Publish the replacement alongside the active keys; promotion waits
        // for the role's hold-down and, for a SEP key, the parent DS check.
        let new_key =
            publish_replacement_key_tx(&mut tx, &signed.zone, template, template.algorithm).await?;
        signed.keys.push(new_key);

        let new_serial = super::resign_zone_tx(
            &mut tx,
            cx,
            &signed,
            SigningPass::Refresh,
            caller.change_attribution(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        build_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await
    }
    .await;
    let response = transaction::finish_tx(tx, result, "failed to start key rollover").await?;

    log::info!("event=dnssec_rollover_start zone={}", response.zone_name);

    // Announce the pre-published key after the signed view commits.
    crate::notify::notify_after_update(cx, zone_name).await;
    Ok(response)
}

/// Pre-publish a replacement for every key with `policy`'s algorithm,
/// double-signing the zone through the transition (RFC 6840, Section
/// 5.11). Returns the key set with the replacements appended.
pub(crate) async fn start_algorithm_rollover_tx(
    tx: &mut Transaction<'_>,
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
        let new_key = publish_replacement_key_tx(tx, zone, template, policy.algorithm).await?;
        keys.push(new_key);
    }
    Ok(keys)
}

/// Promote published SEP keys and retire their predecessors after parent-DS confirmation
/// and hold-down; `ds_check` and `holddown` select which checks the operator waives.
pub async fn advance_rollover(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
    ds_check: DsCheck,
    holddown: Holddown,
) -> Result<DnssecStatusResponse, ServiceError> {
    caller.authorize_global("manage DNSSEC signing")?;

    let mut tx = transaction::begin_tx(cx, "failed to advance key rollover").await?;
    let result = async {
        let mut signed =
            super::lookup_signed_zone_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
        let awaiting = promotable_sep_key_ids(&signed, holddown)?;
        // The answer that confirms the DS also says how long resolvers
        // cache it — the wait the key it replaces must outlive.
        let mut parent_ds_ttl = None;
        if ds_check == DsCheck::Probe {
            let delegation = super::probe_delegation(cx, &signed).await?;
            parent_ds_ttl = delegation.ds_ttl;
            let unconfirmed: Vec<&DnssecDelegationKeyInfo> = delegation
                .keys
                .iter()
                .filter(|key| awaiting.contains(&key.id) && !key.ds_published)
                .collect();
            let unsupported: Vec<KeyTag> = unconfirmed
                .iter()
                .filter(|key| key.ds_digest_unsupported)
                .map(|key| key.key_tag)
                .collect();
            if !unsupported.is_empty() {
                return Err(ServiceError::dnssec_ds_digest_unsupported(
                    signed.zone.name.as_str(),
                    &unsupported,
                ));
            }
            let missing: Vec<KeyTag> = unconfirmed.iter().map(|key| key.key_tag).collect();
            if !missing.is_empty() {
                return Err(ServiceError::dnssec_ds_not_published(
                    signed.zone.name.as_str(),
                    &missing,
                ));
            }
        }
        signed.keys =
            promote_published_keys_tx(&mut tx, &signed.zone, signed.keys, &awaiting, parent_ds_ttl)
                .await?;

        let new_serial = super::resign_zone_tx(
            &mut tx,
            cx,
            &signed,
            SigningPass::Refresh,
            caller.change_attribution(),
        )
        .await?
        .unwrap_or(signed.zone.serial);

        build_status_tx(
            &mut tx,
            &signed.zone,
            Some(&signed.policy),
            &signed.keys,
            new_serial,
        )
        .await
    }
    .await;
    let response = transaction::finish_tx(tx, result, "failed to advance key rollover").await?;

    if ds_check == DsCheck::Skip {
        log::warn!(
            "event=dnssec_rollover_ds_seen_ds_check_skipped zone={}",
            response.zone_name
        );
    }
    if holddown == Holddown::Skip {
        log::warn!(
            "event=dnssec_rollover_ds_seen_holddown_skipped zone={}",
            response.zone_name
        );
    }
    log::info!("event=dnssec_rollover_ds_seen zone={}", response.zone_name);
    crate::notify::notify_after_update(cx, zone_name).await;
    Ok(response)
}

/// Publish a replacement for `template` with `algorithm`. Promotion waits
/// for the DNSKEY TTL; algorithm rollovers may require signing before then.
pub(crate) async fn publish_replacement_key_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    template: &DnssecKey,
    algorithm: DnssecAlgorithm,
) -> Result<DnssecKey, ServiceError> {
    let now = Utc::now();
    let publish_wait = Duration::seconds(i64::from(zone.default_ttl.as_secs()));
    let new_key = DnssecKey::generate(
        zone,
        algorithm,
        template.role,
        DnssecKeyState::Published,
        now,
        now + publish_wait,
    )
    .map_err(ServiceError::dnssec_signing_failed)?;
    Ok(bindizr_db::dnssec_key::create_tx(tx, new_key).await?)
}

/// Promote the published keys named by `promoted` — drawn from this
/// transaction's key list — and retire the active keys of the same roles.
pub(crate) async fn promote_published_keys_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    keys: Vec<DnssecKey>,
    promoted: &[DnssecKeyId],
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
            bindizr_db::dnssec_key::update_state_tx(tx, key.id, DnssecKeyState::Active, now, now)
                .await?;
            key.state = DnssecKeyState::Active;
            key.state_changed_at = now;
            key.eligible_at = now;
        } else if key.state == DnssecKeyState::Active && promoted_roles.contains(&key.role) {
            let eligible_at = now + Duration::seconds(retire_wait);
            bindizr_db::dnssec_key::update_state_tx(
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

/// Return promotable SEP keys or reject absent, ZSK-only, or still-waiting rollovers.
/// The scheduler treats these rejections as idle; `ds-seen` reports them.
pub(crate) fn promotable_sep_key_ids(
    signed: &SignedZone,
    holddown: Holddown,
) -> Result<Vec<DnssecKeyId>, ServiceError> {
    if !signed
        .keys
        .iter()
        .any(|key| key.state == DnssecKeyState::Published)
    {
        return Err(ServiceError::dnssec_no_rollover_in_progress(
            signed.zone.name.as_str(),
        ));
    }
    // ZSKs have no parent DS to confirm; their own step promotes them.
    let awaiting: Vec<&DnssecKey> = signed
        .keys
        .iter()
        .filter(|key| key.awaits_parent_ds())
        .collect();
    // The deadline stamped at publication is authoritative: a later TTL
    // change cannot shorten it (status reports it).
    let Some(promotable_at) = awaiting.iter().map(|key| key.eligible_at).max() else {
        return Err(ServiceError::invalid_input(
            "this rollover replaces the ZSK, which involves no parent DS; it is promoted \
             automatically after the publish hold-down",
        ));
    };
    let ds_published: Vec<DnssecKeyId> = awaiting.iter().map(|key| key.id).collect();
    if holddown == Holddown::Wait && promotable_at > Utc::now() {
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
