//! The parent side of a signed zone: asking its nameservers for the DS.

use bindizr_core::dns::{
    address::is_address_target,
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
        let probed_parent_ns_addrs = zone.parent_ns_addrs;
        let probed_sep_ids = sep_key_ids(&keys);

        let mut tx = RepositoryService::begin_read_tx("failed to check the parent DS").await?;
        let result = async {
            let (zone, policy, keys) =
                Self::get_signed_zone_tx(&mut tx, zone_name, LockLevel::Shared).await?;
            // The status must describe the zone the parent was asked about.
            if zone.parent_ns_addrs != probed_parent_ns_addrs
                || sep_key_ids(&keys) != probed_sep_ids
            {
                return Err(ServiceError::dnssec_state_changed(zone.name.as_str()));
            }
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

/// The ids of the zone's SEP keys, ordered: what a parent's DS can name.
fn sep_key_ids(keys: &[DnssecKey]) -> Vec<i32> {
    let mut ids: Vec<i32> = keys
        .iter()
        .filter(|key| key.role.is_sep())
        .map(|key| key.id)
        .collect();
    ids.sort_unstable();
    ids
}

/// The width of the `zones.parent_ns_addrs` column.
const MAX_PARENT_NS_ADDRS_LEN: usize = 1024;

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
        if has_whitespace_or_control(entry) || !is_address_target(entry) {
            return Err(ServiceError::invalid_input(format!(
                "parent address '{}' must be host[:port] with a numeric port",
                entry
            )));
        }
    }
    let joined = entries.join(",");
    if joined.len() > MAX_PARENT_NS_ADDRS_LEN {
        return Err(ServiceError::invalid_input(format!(
            "parent nameserver list is {} characters; at most {} are stored",
            joined.len(),
            MAX_PARENT_NS_ADDRS_LEN
        )));
    }
    Ok(Some(joined))
}

#[cfg(test)]
mod tests {
    use super::normalize_parent_ns_addrs;
    use crate::error::ErrorCode;

    #[test]
    fn normalize_parent_ns_addrs_trims_entries_and_clears_on_an_empty_list() {
        assert_eq!(
            normalize_parent_ns_addrs(Some(" ns1.parent.example , ns2.parent.example:5353 "))
                .unwrap()
                .as_deref(),
            Some("ns1.parent.example,ns2.parent.example:5353")
        );
        assert_eq!(normalize_parent_ns_addrs(Some(" , ")).unwrap(), None);
        assert_eq!(normalize_parent_ns_addrs(None).unwrap(), None);
    }

    #[test]
    fn normalize_parent_ns_addrs_rejects_an_entry_that_is_not_an_address_target() {
        let err = normalize_parent_ns_addrs(Some("ns.parent.example:not-a-port")).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn normalize_parent_ns_addrs_rejects_a_list_wider_than_the_column() {
        let entry = format!("{}.parent.example", "n".repeat(60));
        let raw = vec![entry.as_str(); 20].join(",");
        let err = normalize_parent_ns_addrs(Some(&raw)).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
