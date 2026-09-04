//! Assembling the status a signed zone reports: its policy, key inventory,
//! and the DS records the parent needs.

use bindizr_core::dns::dnssec::{ds_rdata_for, to_wire_name};
use chrono::{DateTime, Utc};

use super::DnssecService;
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecKey, DnssecKeyState},
        dnssec_policy::DnssecPolicy,
        zone::Zone,
    },
    repository::{RepositoryService, RepositoryTx},
    types::{DnssecDsInfo, DnssecKeyInfo, GetDnssecPolicyResponse, GetDnssecStatusResponse},
    zone::ZoneService,
};

impl DnssecService {
    /// DNSSEC signing state of a zone; `enabled: false` with no policy and
    /// empty key and DS lists for an unsigned zone.
    pub async fn get_status(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        // The DS records are derived from the apex name and the keys, so they
        // are read together under the zone lock.
        let mut tx = RepositoryService::begin_read_tx("failed to read DNSSEC status").await?;
        let result = async {
            let zone = ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Shared).await?;
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            let policy = Self::find_zone_policy_tx(&mut tx, &zone).await?;
            build_status_tx(&mut tx, &zone, policy.as_ref(), &keys, zone.serial).await
        }
        .await;
        RepositoryService::finish_tx(tx, result, "failed to read DNSSEC status").await
    }

    /// Count the zones serving a signed view.
    pub async fn count_signed_zones(caller: &Caller) -> Result<u64, ServiceError> {
        caller.require_global("read DNSSEC metrics")?;
        RepositoryService::count_dnssec_record_zone_ids().await
    }

    /// Count keys in `state` across every zone.
    pub async fn count_keys_by_state(
        caller: &Caller,
        state: DnssecKeyState,
    ) -> Result<u64, ServiceError> {
        caller.require_global("read DNSSEC metrics")?;
        RepositoryService::count_dnssec_keys_by_state(state).await
    }

    /// Count signatures inside their policy's re-sign window across every
    /// zone.
    pub async fn count_rrsigs_expiring_within_refresh(
        caller: &Caller,
        now: DateTime<Utc>,
    ) -> Result<u64, ServiceError> {
        caller.require_global("read DNSSEC metrics")?;
        RepositoryService::count_rrsig_dnssec_records_expiring_within_refresh(now).await
    }

    pub(crate) async fn earliest_expiry_tx(
        tx: &mut RepositoryTx<'_>,
        zone_id: i32,
    ) -> Result<Option<DateTime<Utc>>, ServiceError> {
        let derived =
            RepositoryService::list_dnssec_records_tx(tx, zone_id, LockLevel::None).await?;
        Ok(derived.iter().filter_map(|row| row.expires_at).min())
    }
}

/// Assemble the zone's status on the caller's transaction: the earliest
/// signature expiry and any pending withdrawal join the rows already loaded.
pub(crate) async fn build_status_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    policy: Option<&DnssecPolicy>,
    keys: &[DnssecKey],
    serial: i32,
) -> Result<GetDnssecStatusResponse, ServiceError> {
    let earliest = DnssecService::earliest_expiry_tx(tx, zone.id).await?;
    let withdrawing = RepositoryService::get_dnssec_withdrawal_tx(tx, zone.id)
        .await?
        .is_some();
    build_status(zone, policy, keys, earliest, serial, withdrawing)
}

fn build_status(
    zone: &Zone,
    policy: Option<&DnssecPolicy>,
    keys: &[DnssecKey],
    earliest_signature_expires_at: Option<DateTime<Utc>>,
    serial: i32,
    withdrawing: bool,
) -> Result<GetDnssecStatusResponse, ServiceError> {
    // The parent needs DS records only for the SEP keys the zone still wants
    // delegated trust for.
    let ds_records = keys
        .iter()
        .filter(|key| key.wants_parent_ds())
        .map(|key| ds_info(zone, key))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(GetDnssecStatusResponse {
        zone_name: zone.name.as_str().to_string(),
        enabled: !keys.is_empty(),
        policy: policy.map(GetDnssecPolicyResponse::from_policy),
        keys: keys
            .iter()
            .map(|key| DnssecKeyInfo {
                id: key.id,
                role: key.role.to_string(),
                state: key.state.to_string(),
                state_changed_at: key.state_changed_at,
                eligible_at: (key.state != DnssecKeyState::Active).then_some(key.eligible_at),
                algorithm: key.algorithm.to_string(),
                key_tag: key.key_tag,
                dnskey: format!(
                    "{} 3 {} {}",
                    key.role.flags(),
                    key.algorithm.to_int(),
                    key.public_key
                ),
                created_at: key.created_at,
            })
            .collect(),
        ds_records,
        earliest_signature_expires_at,
        serial,
        withdrawing,
    })
}

/// The key's DS form, decoded from the same RDATA the CDS records carry.
pub(crate) fn ds_info(zone: &Zone, key: &DnssecKey) -> Result<DnssecDsInfo, ServiceError> {
    let apex = to_wire_name(zone.name.to_wire())
        .map_err(|e| ServiceError::internal(format!("invalid zone apex: {}", e)))?;
    let rdata = ds_rdata_for(key, &apex).map_err(ServiceError::dnssec_signing_failed)?;
    let digest = hex::encode_upper(&rdata.as_bytes()[4..]);

    Ok(DnssecDsInfo {
        key_tag: key.key_tag,
        algorithm: key.algorithm.to_int() as u8,
        digest_type: key.algorithm.ds_digest_type(),
        digest: digest.clone(),
        presentation: format!(
            "{} IN DS {} {} {} {}",
            zone.name.to_fqdn(),
            key.key_tag,
            key.algorithm.to_int(),
            key.algorithm.ds_digest_type(),
            digest
        ),
    })
}
