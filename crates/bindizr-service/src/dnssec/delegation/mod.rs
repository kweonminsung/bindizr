//! The parent side of a signed zone: asking its nameservers for the DS.

use bindizr_core::dns::{dnssec::DS_DIGEST_TYPES, query::DsRecordSet};
use chrono::Utc;

use super::{DnssecService, status::build_status_tx};
use crate::{
    authorization::Caller,
    database::repository::LockLevel,
    dns_client::ds::{ParentDs, probe_parent_ds},
    dnssec::SignedZone,
    error::ServiceError,
    model::{
        dnssec_key::{DnssecKey, DnssecKeyState},
        zone::Zone,
    },
    repository::RepositoryService,
    types::{DnssecDelegationInfo, DnssecDelegationKeyInfo, DnssecStatusResponse, DsState},
};

impl DnssecService {
    /// Ask the zone's parent whether it serves the zone's DS, reporting the
    /// answer with the zone's status.
    pub async fn check_ds(
        caller: &Caller,
        zone_name: &str,
    ) -> Result<DnssecStatusResponse, ServiceError> {
        caller.authorize_global("manage DNSSEC signing")?;

        let mut tx = RepositoryService::begin_read_tx("failed to check the parent DS").await?;
        let result = async {
            let signed = Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Shared).await?;
            let status = build_status_tx(
                &mut tx,
                &signed.zone,
                Some(&signed.policy),
                &signed.keys,
                signed.zone.serial,
            )
            .await?;
            Ok((signed, status))
        }
        .await;
        let (signed, mut status) =
            RepositoryService::finish_tx(tx, result, "failed to check the parent DS").await?;
        // Read-only, so the wait stays outside the transaction; the keys are
        // the ones the status describes.
        status.delegation = Some(Self::probe_delegation(&signed).await?);
        Ok(status)
    }

    /// The parent's answer about the zone's DS, matched against the zone's
    /// SEP keys, or the unverified error a refusal reports.
    pub(crate) async fn probe_delegation(
        signed: &SignedZone,
    ) -> Result<DnssecDelegationInfo, ServiceError> {
        let parent = probe_parent_ds(&signed.zone)
            .await
            .map_err(|e| ServiceError::dnssec_ds_unverified(signed.zone.name.as_str(), e))?;

        build_delegation_info(&signed.zone, &signed.keys, parent)
    }
}

/// Match the parent's answers against the zone's SEP keys. Refusal and
/// promotion read them in opposite directions — a DS at any one server blocks
/// a disable, promotion waits for every one — so a parent still propagating
/// the change cannot move the zone the unsafe way in either direction.
fn build_delegation_info(
    zone: &Zone,
    keys: &[DnssecKey],
    parent: ParentDs,
) -> Result<DnssecDelegationInfo, ServiceError> {
    let served: Vec<&DsRecordSet> = parent.answers.iter().flatten().collect();
    let mut ds_key_tags: Vec<u16> = served
        .iter()
        .flat_map(|record_set| record_set.key_tags())
        .collect();
    ds_key_tags.sort_unstable();
    ds_key_tags.dedup();

    let apex = zone
        .name
        .to_wire_name()
        .map_err(|e| ServiceError::internal(format!("invalid zone apex: {}", e)))?;

    let mut delegation_keys = Vec::new();
    for key in keys.iter().filter(|key| key.role.is_sep()) {
        // Whole RDATA, since keys can share a tag; in the digest types
        // the parent serves, since the parent picks; at every server, so
        // a laggard cannot promote a key early.
        let mut digest_types: Vec<u8> = served
            .iter()
            .flat_map(|record_set| record_set.records.iter())
            .filter(|record| record.key_tag == key.key_tag as u16)
            .map(|record| record.digest_type)
            .filter(|digest_type| DS_DIGEST_TYPES.contains(digest_type))
            .collect();
        digest_types.sort_unstable();
        digest_types.dedup();

        // A digest bindizr cannot compute leaves the match undecided, not
        // absent. Per server, so one computable answer cannot mask another.
        let ds_digest_unsupported = parent.answers.iter().any(|answer| {
            answer.as_ref().is_some_and(|record_set| {
                let mut for_key = record_set
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
                key.ds_rdata(&apex, *digest_type)
                    .map(|rdata| rdata.as_bytes().to_vec())
                    .map_err(ServiceError::dnssec_signing_failed)
            })
            .collect::<Result<Vec<Vec<u8>>, ServiceError>>()?;

        let ds_published = !parent.answers.is_empty()
            && parent.answers.iter().all(|answer| {
                answer.as_ref().is_some_and(|record_set| {
                    record_set
                        .records
                        .iter()
                        .any(|record| forms.contains(&record.rdata))
                })
            });

        delegation_keys.push(DnssecDelegationKeyInfo {
            id: key.id,
            key_tag: key.key_tag as u16,
            role: key.role,
            state: key.state,
            ds_published,
            ds_digest_unsupported,
            eligible_at: (key.state == DnssecKeyState::Published).then_some(key.eligible_at),
        });
    }

    Ok(DnssecDelegationInfo {
        parent_ns_addrs: parent.ns_addrs,
        ds_state: if served.is_empty() {
            DsState::Hidden
        } else {
            DsState::Published
        },
        keys: delegation_keys,
        ds_key_tags,
        ds_ttl: served.iter().map(|record_set| record_set.ttl).max(),
        checked_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests;
