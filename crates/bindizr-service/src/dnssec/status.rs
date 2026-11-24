//! Assembling the status a signed zone reports: its policy, key inventory,
//! and the DS records the parent needs.

use bindizr_core::dns::Serial;
use bindizr_core::dns::dnssec::DS_DIGEST_TYPE;
use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::dnssec_key::{DnssecKey, DnssecKeyState};
use bindizr_core::model::dnssec_policy::DnssecPolicy;
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
use bindizr_db::LockLevel;
use chrono::{DateTime, Utc};

use crate::authorization::Caller;
use crate::dnssec::parent_ns_addrs;
use crate::error::ServiceError;
use crate::types::{
    DnssecDsResponse, DnssecKeyResponse, DnssecPolicyResponse, DnssecStatusResponse,
};
use crate::{Context, Transaction, dnssec, transaction, zone};

/// Get the DNSSEC signing state of a zone; `enabled: false` with no policy and
/// empty key and DS lists for an unsigned zone.
pub async fn get_status(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<DnssecStatusResponse, ServiceError> {
    // The DS records are derived from the apex name and the keys, so they
    // are read together under the zone lock.
    let mut tx = transaction::begin_read_tx(cx, "failed to read DNSSEC status").await?;

    let result: Result<_, ServiceError> = async {
        let zone = zone::lookup_by_name_tx(&mut tx, zone_name, LockLevel::Shared).await?;
        caller
            .reauthenticate_tx(&mut tx)
            .await?
            .authorize_zone_action(Action::DnssecRead, &zone)?;
        let keys = bindizr_db::dnssec_key::list_tx(&mut tx, zone.id).await?;
        let policy = dnssec::find_zone_policy_tx(&mut tx, &zone).await?;

        lookup_status_tx(&mut tx, &zone, policy.as_ref(), &keys, zone.serial).await
    }
    .await;

    transaction::finish_tx(tx, result, "failed to read DNSSEC status").await
}

/// Count the zones serving a signed view, for the unauthenticated metrics endpoint.
pub async fn count_signed_zones(cx: &Context) -> Result<u64, ServiceError> {
    Ok(bindizr_db::dnssec_record::count_zone_ids(cx.db()).await?)
}

/// Count the keys in `state` across all zones, for the metrics endpoint.
pub async fn count_keys_by_state(cx: &Context, state: DnssecKeyState) -> Result<u64, ServiceError> {
    Ok(bindizr_db::dnssec_key::count_by_state(cx.db(), state).await?)
}

/// Count signatures inside their policy's re-sign window across all zones.
pub async fn count_rrsigs_expiring_within_refresh(
    cx: &Context,
    now: DateTime<Utc>,
) -> Result<u64, ServiceError> {
    Ok(bindizr_db::dnssec_record::count_expiring_within_refresh(cx.db(), now).await?)
}

/// Count the signatures already past their expiration across all zones; any
/// at all mean resolvers are failing part of one right now.
pub async fn count_rrsigs_expired(cx: &Context, now: DateTime<Utc>) -> Result<u64, ServiceError> {
    Ok(bindizr_db::dnssec_record::count_expired_before(cx.db(), now).await?)
}

/// Look up the zone's status on the caller's transaction: the earliest
/// signature expiry and any pending withdrawal join the rows already loaded.
pub(crate) async fn lookup_status_tx(
    tx: &mut Transaction<'_>,
    zone: &Zone,
    policy: Option<&DnssecPolicy>,
    keys: &[DnssecKey],
    serial: Serial,
) -> Result<DnssecStatusResponse, ServiceError> {
    let derived = bindizr_db::dnssec_record::list_tx(tx, zone.id).await?;
    let earliest_signature_expires_at = derived.iter().filter_map(|record| record.expires_at).min();

    // Only RRSIG rows carry an expiration, so counting those counts signatures.
    let now = Utc::now();
    let signatures = derived
        .iter()
        .filter(|record| record.expires_at.is_some())
        .count() as u64;
    let expired_signatures = derived
        .iter()
        .filter(|record| record.expires_at.is_some_and(|expires| expires <= now))
        .count() as u64;
    let next_resign_at = earliest_signature_expires_at
        .zip(policy)
        .map(|(expires, policy)| expires - policy.signature_refresh_days.to_duration());

    let withdrawing = bindizr_db::dnssec_withdrawal::get_tx(tx, zone.id)
        .await?
        .is_some();

    // The parent needs DS records only for the SEP keys the zone still wants
    // delegated trust for.
    let ds_records: Vec<_> = keys
        .iter()
        .filter(|key| key.wants_parent_ds())
        .map(|key| build_ds_response(zone, key))
        .collect::<Result<_, _>>()?;

    Ok(DnssecStatusResponse {
        zone_name: zone.name.to_string(),
        enabled: !keys.is_empty(),
        policy: policy.map(DnssecPolicyResponse::from),
        keys: keys.iter().map(DnssecKeyResponse::from).collect(),
        ds_records,
        earliest_signature_expires_at,
        signatures,
        expired_signatures,
        next_resign_at,
        serial,
        withdrawing,
        parent_ns_addrs: zone.parent_ns_addrs.as_deref().map(parent_ns_addrs::split),
        delegation: None,
    })
}

/// Build the key's DS form from the same digest the CDS records carry.
fn build_ds_response(zone: &Zone, key: &DnssecKey) -> Result<DnssecDsResponse, ServiceError> {
    let apex = zone
        .name
        .to_wire_name()
        .map_err(|error| ServiceError::internal_with_source("invalid zone apex", error))?;
    let ds = key
        .to_ds(&apex, DS_DIGEST_TYPE)
        .map_err(ServiceError::dnssec_signing_failed)?;

    Ok(DnssecDsResponse {
        key_tag: key.key_tag,
        algorithm: key.algorithm.as_u8(),
        digest_type: DS_DIGEST_TYPE.as_u8(),
        digest: hex::encode_upper(ds.digest()),
        presentation: format!("{} IN DS {}", zone.name.to_fqdn(), ds.to_text()),
    })
}
