//! The parent side of a signed zone: asking its nameservers for the DS.

use bindizr_core::dns::{
    dnssec::{DS_DIGEST_TYPES, ds_rdata_for, to_wire_name},
    query::DsRrset,
};
use chrono::Utc;

use super::{DnssecService, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dns_client::ds::{ParentDs, probe_parent_ds},
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

        let mut tx = RepositoryService::begin_read_tx("failed to check the parent DS").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Shared).await?;
            let status = build_status_tx(&mut tx, &zone, Some(&policy), &keys, zone.serial).await?;
            Ok((zone, keys, status))
        }
        .await;
        let (zone, keys, mut status) =
            RepositoryService::finish_tx(tx, result, "failed to check the parent DS").await?;
        // Read-only, so the wait stays outside the transaction; the keys are
        // the ones the status describes.
        status.delegation = Some(Self::probe_delegation(&zone, &keys).await?);
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

        to_delegation_info(zone, keys, parent)
    }
}

/// Match the parent's answers against the zone's SEP keys. Refusal and
/// promotion read them in opposite directions — a DS at any one server blocks
/// a disable, promotion waits for every one — so a parent still propagating
/// the change cannot move the zone the unsafe way in either direction.
fn to_delegation_info(
    zone: &Zone,
    keys: &[DnssecKey],
    parent: ParentDs,
) -> Result<DnssecDelegationInfo, ServiceError> {
    let served: Vec<&DsRrset> = parent.answers.iter().flatten().collect();
    let mut ds_key_tags: Vec<u16> = served.iter().flat_map(|rrset| rrset.key_tags()).collect();
    ds_key_tags.sort_unstable();
    ds_key_tags.dedup();

    let apex = to_wire_name(zone.name.to_wire())
        .map_err(|e| ServiceError::internal(format!("invalid zone apex: {}", e)))?;

    let mut delegation_keys = Vec::new();
    for key in keys.iter().filter(|key| key.role.is_sep()) {
        // Whole RDATA, since keys can share a tag; in the digest types
        // the parent serves, since the parent picks; at every server, so
        // a laggard cannot promote a key early.
        let mut digest_types: Vec<u8> = served
            .iter()
            .flat_map(|rrset| rrset.records.iter())
            .filter(|record| record.key_tag == key.key_tag as u16)
            .map(|record| record.digest_type)
            .filter(|digest_type| DS_DIGEST_TYPES.contains(digest_type))
            .collect();
        digest_types.sort_unstable();
        digest_types.dedup();

        // A digest bindizr cannot compute leaves the match undecided, not
        // absent. Per server, so one computable answer cannot mask another.
        let ds_digest_unsupported = parent.answers.iter().any(|answer| {
            answer.as_ref().is_some_and(|rrset| {
                let mut for_key = rrset
                    .records
                    .iter()
                    .filter(|record| record.key_tag == key.key_tag as u16)
                    .peekable();
                for_key.peek().is_some()
                    && !for_key.any(|record| DS_DIGEST_TYPES.contains(&record.digest_type))
            })
        });

        let forms = digest_types
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
            ds_digest_unsupported,
            eligible_at: (key.state == DnssecKeyState::Published).then_some(key.eligible_at),
        });
    }

    Ok(DnssecDelegationInfo {
        parent_ns_addrs: parent.ns_addrs,
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

#[cfg(test)]
mod tests;
