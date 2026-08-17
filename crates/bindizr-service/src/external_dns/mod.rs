//! ExternalDNS provider integration: authoritative zone matching and atomic
//! RRset change application behind the `/external-dns` HTTP API (consumed by
//! the bindizr-external-dns adapter). Which zones a caller may see and change
//! is decided by its token's zone policies, like every other endpoint.

mod apply;
mod policy;
#[cfg(test)]
mod tests;

use std::collections::HashMap;

use crate::{
    authorization::Caller,
    error::ServiceError,
    model::zone::Zone,
    repository::RepositoryService,
    types::{ExternalDnsAdjustRequest, ExternalDnsAdjustResponse, ExternalDnsRecordItem},
};

/// Business logic for the ExternalDNS provider API.
pub struct ExternalDnsService;

impl ExternalDnsService {
    /// Canonicalize desired RRsets to the form applying them would store, so
    /// the adapter's AdjustEndpoints answer cannot drift from the server's
    /// normalization. Takes no caller: it only normalizes the request's own
    /// payload.
    pub fn adjust_rrsets(
        request: &ExternalDnsAdjustRequest,
    ) -> Result<ExternalDnsAdjustResponse, ServiceError> {
        let rrsets = request
            .rrsets
            .iter()
            .map(apply::adjust_rrset)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ExternalDnsAdjustResponse { rrsets })
    }

    /// Names of the zones the caller may manage.
    pub async fn list_zones(caller: &Caller) -> Result<Vec<String>, ServiceError> {
        let visible = caller.visible_zone_ids();
        let zones = RepositoryService::list_zones().await?;
        Ok(zones
            .into_iter()
            .filter(|zone| visible.as_ref().is_none_or(|ids| ids.contains(&zone.id)))
            .map(|zone| zone.name.to_string())
            .collect())
    }

    /// Records of every zone the caller may manage, restricted to the
    /// ExternalDNS-supported record types, with absolute owner names and
    /// presentation-form values.
    pub async fn list_records(caller: &Caller) -> Result<Vec<ExternalDnsRecordItem>, ServiceError> {
        let visible = caller.visible_zone_ids();
        let zones = RepositoryService::list_zones().await?;
        let zones_by_id: HashMap<i32, &Zone> = zones
            .iter()
            .filter(|zone| visible.as_ref().is_none_or(|ids| ids.contains(&zone.id)))
            .map(|zone| (zone.id, zone))
            .collect();

        // One batched query; a round trip per zone stalls large deployments.
        let zone_ids: Vec<i32> = zones_by_id.keys().copied().collect();
        let records = RepositoryService::list_records_by_zone_ids(&zone_ids).await?;

        let mut items = Vec::new();
        for record in records {
            if !apply::is_supported_record_type(&record.record_type) {
                continue;
            }
            let Some(zone) = zones_by_id.get(&record.zone_id) else {
                continue;
            };
            items.push(ExternalDnsRecordItem {
                name: record
                    .name
                    .clone()
                    .to_fqdn(&zone.name)
                    .trim_end_matches('.')
                    .to_string(),
                record_type: record.record_type.to_string(),
                ttl: record.ttl,
                value: record
                    .record_type
                    .presentation_rdata(&record.value, record.priority),
            });
        }

        // Deterministic order so an unchanged state never reads as a diff.
        items.sort_by(|a, b| {
            (&a.name, &a.record_type, &a.value).cmp(&(&b.name, &b.record_type, &b.value))
        });
        Ok(items)
    }
}
