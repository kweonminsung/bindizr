//! The parent side of a signed zone: asking its nameservers for the DS.

use bindizr_core::dns::dnssec::{DsDigestType, KeyTag};
use bindizr_core::dns::name::ZoneName;
use bindizr_core::dns::query::DsRecordSet;
use bindizr_core::dns::record::Rdata;
use bindizr_core::model::activity_log::{ActivityOperation, ActivityResult};
use bindizr_core::model::dnssec_key::{DnssecKey, DnssecKeyState};
use bindizr_core::model::role_grant::Action;
use bindizr_core::model::zone::Zone;
use bindizr_db::LockLevel;
use chrono::Utc;
use thiserror::Error;

use crate::authorization::Caller;
use crate::dns_client::ds;
use crate::dns_client::ds::ParentDsAnswer;
use crate::dnssec::SignedZone;
use crate::error::ServiceError;
use crate::types::{
    DnssecDelegationKeyResponse, DnssecDelegationResponse, DnssecStatusResponse, DsState,
};
use crate::{Context, activity, dnssec, transaction, zone};

/// Why the zone's configuration prevents a delegation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
enum ProbeDelegationError {
    #[error("the zone names no parent nameservers")]
    NoParentNameservers,
}

/// Ask the zone's parent whether it serves the zone's DS, reporting the
/// answer with the zone's status.
pub async fn check_ds(
    cx: &Context,
    caller: &Caller,
    zone_name: &ZoneName,
) -> Result<DnssecStatusResponse, ServiceError> {
    let mut tx = transaction::begin_read_tx(cx, "failed to check the parent DS").await?;

    let result: Result<_, ServiceError> = async {
        let signed = dnssec::get_signed_zone_tx(
            &mut tx,
            caller,
            Action::DnssecRead,
            zone_name,
            LockLevel::Shared,
        )
        .await?;
        let status = dnssec::lookup_status_tx(
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
        transaction::finish_tx(tx, result, "failed to check the parent DS").await?;

    // Read-only, so the wait stays outside the transaction; the keys are
    // the ones the status describes.
    status.delegation = Some(probe_delegation(cx, &signed).await?);
    activity::save_result(
        cx,
        ActivityOperation::DnssecCheckDs,
        ActivityResult::Succeeded,
        zone::activity_target(zone_name),
        caller.change_origin(),
    )
    .await;

    Ok(status)
}

/// Probe the parent for the zone's DS, matched against the zone's SEP keys,
/// or return the unverified error a refusal reports.
pub(crate) async fn probe_delegation(
    cx: &Context,
    signed: &SignedZone,
) -> Result<DnssecDelegationResponse, ServiceError> {
    let parent_ns_addrs = signed.zone.parent_ns_addrs.as_deref().ok_or_else(|| {
        ServiceError::dnssec_ds_unverified(
            &signed.zone.name,
            ProbeDelegationError::NoParentNameservers,
        )
    })?;
    let timeout = cx.config().dns.notify.timeout();

    let parent = ds::probe_parent_ds(&signed.zone.name, parent_ns_addrs, timeout)
        .await
        .map_err(|error| ServiceError::dnssec_ds_unverified(&signed.zone.name, error))?;

    build_delegation_response(&signed.zone, &signed.keys, parent)
}

/// Match parent answers against SEP keys: any DS blocks disabling, all servers must confirm promotion.
/// This keeps both transitions safe while parent changes propagate.
fn build_delegation_response(
    zone: &Zone,
    keys: &[DnssecKey],
    answers: Vec<ParentDsAnswer>,
) -> Result<DnssecDelegationResponse, ServiceError> {
    let served: Vec<&DsRecordSet> = answers
        .iter()
        .filter_map(|answer| answer.records.as_ref())
        .collect();
    let mut ds_key_tags: Vec<KeyTag> = served
        .iter()
        .flat_map(|record_set| record_set.key_tags())
        .collect();
    ds_key_tags.sort_unstable();
    ds_key_tags.dedup();

    let apex = zone
        .name
        .to_wire_name()
        .map_err(|error| ServiceError::internal_with_source("invalid zone apex", error))?;

    let mut delegation_keys = Vec::new();

    for key in keys.iter().filter(|key| key.role.is_sep()) {
        // Compare full RDATA to avoid key-tag collisions, using the parent's digest types.
        // Require every server to agree before promoting a key.
        let mut digest_types: Vec<DsDigestType> = served
            .iter()
            .flat_map(|record_set| record_set.records.iter())
            .filter(|record| record.key_tag == key.key_tag)
            .filter_map(|record| DsDigestType::try_from(record.digest_type).ok())
            .collect();
        digest_types.sort_unstable();
        digest_types.dedup();

        // A digest bindizr cannot compute leaves the match undecided, not
        // absent. Per server, so one computable answer cannot mask another.
        let ds_digest_unsupported = served.iter().any(|record_set| {
            let mut for_key = record_set
                .records
                .iter()
                .filter(|record| record.key_tag == key.key_tag)
                .peekable();
            for_key.peek().is_some()
                && !for_key.any(|record| DsDigestType::try_from(record.digest_type).is_ok())
        });

        let forms: Vec<Vec<u8>> = digest_types
            .iter()
            .map(|digest_type| {
                key.ds_rdata(&apex, *digest_type)
                    .map(Rdata::into_bytes)
                    .map_err(ServiceError::dnssec_signing_failed)
            })
            .collect::<Result<_, ServiceError>>()?;

        let ds_published = !answers.is_empty()
            && served.len() == answers.len()
            && served.iter().all(|record_set| {
                record_set
                    .records
                    .iter()
                    .any(|record| forms.contains(&record.rdata))
            });

        delegation_keys.push(DnssecDelegationKeyResponse {
            id: key.id,
            key_tag: key.key_tag,
            role: key.role,
            state: key.state,
            ds_published,
            ds_digest_unsupported,
            eligible_at: (key.state == DnssecKeyState::Published).then_some(key.eligible_at),
        });
    }

    let ds_state = if served.is_empty() {
        DsState::Hidden
    } else {
        DsState::Published
    };
    let ds_ttl = served.iter().map(|record_set| record_set.ttl).max();
    Ok(DnssecDelegationResponse {
        parent_ns_addrs: answers.into_iter().map(|answer| answer.server).collect(),
        ds_state,
        keys: delegation_keys,
        ds_key_tags,
        ds_ttl,
        checked_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests;
