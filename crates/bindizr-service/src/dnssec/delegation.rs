//! The parent side of a signed zone: asking its nameservers for the DS.

use bindizr_core::dns::{
    dnssec::{ds_rdata_for, to_wire_name},
    query::DsRrset,
};
use chrono::{DateTime, Utc};

use super::{DnssecService, snapshot::ProbedSnapshot, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dns_client::ds::probe_parent_ds,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecKey, DnssecKeyState},
        zone::Zone,
    },
    repository::RepositoryService,
    types::{DnssecDelegationInfo, DnssecDelegationKeyInfo, GetDnssecStatusResponse},
};

impl DnssecService {
    /// Ask the zone's parent whether it serves the zone's DS, reporting the
    /// answer with the zone's status.
    pub async fn check_ds(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;

        // Read unlocked: the probe's network wait must not hold the zone row.
        let (zone, keys) = {
            let mut tx = RepositoryService::begin_read_tx("failed to check the parent DS").await?;
            let result = Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::None)
                .await
                .map(|(zone, _, keys)| (zone, keys));
            RepositoryService::finish_tx(tx, result, "failed to check the parent DS").await?
        };
        let delegation = Self::probe_delegation(&zone, &keys).await?;
        // The delegation entries describe these keys in these states.
        let snapshot = ProbedSnapshot::take(&zone, &keys, |zone, keys| {
            Ok((zone.parent_ns_addrs.clone(), sep_key_states(keys)))
        })?;

        let mut tx = RepositoryService::begin_read_tx("failed to check the parent DS").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Shared).await?;
            snapshot.require_same(&zone, &keys)?;
            build_status_tx(&mut tx, &zone, Some(&policy), &keys, zone.serial).await
        }
        .await;
        let mut status =
            RepositoryService::finish_tx(tx, result, "failed to check the parent DS").await?;
        status.delegation = Some(delegation);
        Ok(status)
    }

    /// The parent's answer about the zone's DS, matched against the zone's
    /// SEP keys, or the unverified error a refusal reports.
    pub(crate) async fn probe_delegation(
        zone: &Zone,
        keys: &[DnssecKey],
    ) -> Result<DnssecDelegationInfo, ServiceError> {
        let parent = probe_parent_ds(zone)
            .await
            .map_err(|e| ServiceError::dnssec_ds_unverified(zone.name.as_str(), e))?;
        let served: Vec<&DsRrset> = parent.answers.iter().flatten().collect();
        let mut ds_key_tags: Vec<u16> = served.iter().flat_map(|rrset| rrset.key_tags()).collect();
        ds_key_tags.sort_unstable();
        ds_key_tags.dedup();
        let apex = to_wire_name(zone.name.to_wire())
            .map_err(|e| ServiceError::internal(format!("invalid zone apex: {}", e)))?;
        let mut delegation_keys = Vec::new();
        for key in keys.iter().filter(|key| key.role.is_sep()) {
            // Whole RDATA, since keys can share a tag; either digest type,
            // since the parent picks; every server, so a laggard cannot
            // promote a key early.
            let forms = [2u8, 4]
                .iter()
                .map(|digest_type| {
                    ds_rdata_for(key, &apex, *digest_type)
                        .map(|rdata| rdata.as_bytes().to_vec())
                        .map_err(ServiceError::dnssec_signing_failed)
                })
                .collect::<Result<Vec<Vec<u8>>, ServiceError>>()?;
            let ds_published = !parent.answers.is_empty()
                && parent.answers.iter().all(|answer| {
                    answer.as_ref().is_some_and(|rrset| {
                        rrset
                            .records
                            .iter()
                            .any(|record| forms.contains(&record.rdata))
                    })
                });
            delegation_keys.push(DnssecDelegationKeyInfo {
                id: key.id,
                key_tag: key.key_tag as u16,
                role: key.role.to_string(),
                state: key.state.to_string(),
                ds_published,
                eligible_at: (key.state == DnssecKeyState::Published).then_some(key.eligible_at),
            });
        }
        Ok(DnssecDelegationInfo {
            parent_ns_addrs: parent.ns_addrs,
            discovered: parent.discovered,
            ds_state: if served.is_empty() {
                "hidden"
            } else {
                "published"
            }
            .to_string(),
            keys: delegation_keys,
            ds_key_tags,
            ds_ttl: served.iter().map(|rrset| rrset.ttl).max(),
            checked_at: Utc::now(),
        })
    }
}

/// The SEP keys as the delegation entries describe them: id, state, and
/// eligibility, ordered by id.
fn sep_key_states(keys: &[DnssecKey]) -> Vec<(i32, DnssecKeyState, DateTime<Utc>)> {
    let mut states: Vec<_> = keys
        .iter()
        .filter(|key| key.role.is_sep())
        .map(|key| (key.id, key.state, key.eligible_at))
        .collect();
    states.sort_unstable_by_key(|(id, _, _)| *id);
    states
}
