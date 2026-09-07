//! The parent side of a signed zone: which servers to ask for its DS, and
//! asking them.

use bindizr_core::dns::name::has_whitespace_or_control;
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
    zone::ZoneService,
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

    /// Set the servers asked whether the parent still serves the zone's DS,
    /// or with `None` return the zone to parent discovery.
    pub async fn set_parent_ns_addrs(
        caller: &Caller,
        zone_name: &str,
        parent_ns_addrs: Option<&str>,
    ) -> Result<GetDnssecStatusResponse, ServiceError> {
        caller.require_global("manage DNSSEC signing")?;
        let parent_ns_addrs = normalize_parent_ns_addrs(parent_ns_addrs)?;

        let mut tx =
            RepositoryService::begin_tx("failed to set the zone's parent nameserver addresses")
                .await?;
        let result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;
            RepositoryService::update_zone_parent_ns_addrs_tx(
                &mut tx,
                zone.id,
                parent_ns_addrs.as_deref(),
            )
            .await?;
            let zone = Zone {
                parent_ns_addrs,
                ..zone
            };
            let keys =
                RepositoryService::list_dnssec_keys_tx(&mut tx, zone.id, LockLevel::None).await?;
            let policy = Self::find_zone_policy_tx(&mut tx, &zone).await?;
            build_status_tx(&mut tx, &zone, policy.as_ref(), &keys, zone.serial).await
        }
        .await;
        let response = RepositoryService::finish_tx(
            tx,
            result,
            "failed to set the zone's parent nameserver addresses",
        )
        .await?;

        crate::log_info!(
            "event=dnssec_set_parent_ns_addrs zone={}",
            response.zone_name
        );
        Ok(response)
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
        let ds_key_tags: Vec<u16> = parent
            .rrset
            .as_ref()
            .map(|rrset| rrset.key_tags.clone())
            .unwrap_or_default();
        Ok(DnssecDelegationInfo {
            parent_servers: parent.servers,
            discovered: parent.discovered,
            ds_state: if parent.rrset.is_some() {
                "published"
            } else {
                "hidden"
            }
            .to_string(),
            keys: keys
                .iter()
                .filter(|key| key.role.is_sep())
                .map(|key| DnssecDelegationKeyInfo {
                    key_tag: key.key_tag as u16,
                    role: key.role.to_string(),
                    state: key.state.to_string(),
                    ds_published: ds_key_tags.contains(&(key.key_tag as u16)),
                    eligible_at: (key.state == DnssecKeyState::Published)
                        .then_some(key.eligible_at),
                })
                .collect(),
            ds_key_tags,
            ds_ttl: parent.rrset.as_ref().map(|rrset| rrset.ttl),
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
