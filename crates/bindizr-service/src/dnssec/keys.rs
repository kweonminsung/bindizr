//! Key generation and the RFC 7583 state transitions: published keys promote
//! to active, and the active keys they replace retire until caches drain.

use base64::Engine;
use bindizr_core::config::bindizr_config;
use chrono::{DateTime, Duration, Utc};

use crate::{
    error::ServiceError,
    log_info,
    model::{
        dnssec_key::{DnssecAlgorithm, DnssecKey, DnssecKeyRole, DnssecKeyState},
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
};

/// Promote published keys (all, or just `only`) and retire the active keys
/// of the same roles; `None` when nothing was promoted.
pub(super) async fn promote_published_keys_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    keys: Vec<DnssecKey>,
    only: Option<&[i32]>,
) -> Result<Option<Vec<DnssecKey>>, ServiceError> {
    let now = Utc::now();
    // The retiring key outlives the signatures it made, which resolvers cache
    // for their RRset's TTL (RFC 7583, Section 3.3.4).
    let retire_wait_floor = bindizr_config().dnssec.rollover_retire_holddown_secs as i64;
    let promoted_ids: Vec<i32> = keys
        .iter()
        .filter(|key| {
            key.state == DnssecKeyState::Published && only.is_none_or(|ids| ids.contains(&key.id))
        })
        .map(|key| key.id)
        .collect();
    if promoted_ids.is_empty() {
        return Ok(None);
    }
    let promoted_roles: Vec<DnssecKeyRole> = keys
        .iter()
        .filter(|key| promoted_ids.contains(&key.id))
        .map(|key| key.role)
        .collect();

    let mut updated = Vec::with_capacity(keys.len());
    for mut key in keys {
        if promoted_ids.contains(&key.id) {
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
        promoted_ids.len(),
        zone.name
    );
    Ok(Some(updated))
}

pub(super) fn generate_key(
    zone: &Zone,
    algorithm: DnssecAlgorithm,
    role: DnssecKeyRole,
    state: DnssecKeyState,
    now: DateTime<Utc>,
    eligible_at: DateTime<Utc>,
) -> Result<DnssecKey, ServiceError> {
    let params = match algorithm {
        DnssecAlgorithm::EcdsaP256Sha256 => domain::crypto::sign::GenerateParams::EcdsaP256Sha256,
        DnssecAlgorithm::Ed25519 => domain::crypto::sign::GenerateParams::Ed25519,
    };
    let (secret, dnskey) = domain::crypto::sign::generate(&params, role.flags())
        .map_err(|e| ServiceError::internal(format!("failed to generate DNSSEC key: {}", e)))?;

    Ok(DnssecKey {
        id: 0,
        zone_id: zone.id,
        role,
        algorithm,
        key_tag: i32::from(dnskey.key_tag()),
        public_key: base64::engine::general_purpose::STANDARD.encode(dnskey.public_key()),
        private_key: secret.display_as_bind().to_string(),
        state,
        state_changed_at: now,
        eligible_at,
        max_signed_ttl: 0,
        created_at: now,
    })
}
