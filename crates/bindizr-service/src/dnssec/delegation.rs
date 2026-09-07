//! The parent side of a signed zone: asking its nameservers for the DS.

use bindizr_core::dns::{
    dnssec::{ds_rdata_for, to_wire_name},
    name::has_whitespace_or_control,
    query::DsRrset,
};
use chrono::Utc;

use super::{DnssecService, status::build_status_tx};
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

        let mut tx = RepositoryService::begin_read_tx("failed to check the parent DS").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Shared).await?;
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
            // Whole-RDATA match, since keys can share a 16-bit tag; and at
            // every server, so a lagging one cannot promote a key early.
            let expected = ds_rdata_for(key, &apex).map_err(ServiceError::dnssec_signing_failed)?;
            let ds_published = !parent.answers.is_empty()
                && parent.answers.iter().all(|answer| {
                    answer.as_ref().is_some_and(|rrset| {
                        rrset
                            .records
                            .iter()
                            .any(|record| record.rdata == expected.as_bytes())
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

/// Trim a comma-separated `host[:port]` list into its stored form; `None` or
/// an empty list clears the zone's parent nameservers.
pub(crate) fn normalize_parent_ns_addrs(raw: Option<&str>) -> Result<Option<String>, ServiceError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let entries: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() {
        return Ok(None);
    }
    for entry in &entries {
        if has_whitespace_or_control(entry) {
            return Err(ServiceError::invalid_input(format!(
                "parent address '{}' must be a host[:port] entry without whitespace",
                entry
            )));
        }
    }
    Ok(Some(entries.join(",")))
}
