//! ExternalDNS provider integration: authoritative zone matching and atomic
//! RRset change application behind the `/external-dns` HTTP API (consumed by
//! the bindizr-external-dns adapter). Which zones a caller may see and change
//! is decided by its token's zone policies, like every other endpoint.

mod apply;
mod policy;
#[cfg(test)]
mod tests;

use bindizr_core::dns::record::{display_record_owner_name, presentation_rdata};

use crate::{
    authorization::{Caller, visible_zone_ids},
    error::ServiceError,
    repository::RepositoryService,
    types::ExternalDnsRecordItem,
};

/// Business logic for the ExternalDNS provider API.
pub struct ExternalDnsService;

impl ExternalDnsService {
    /// Names of the zones the caller may manage.
    pub async fn list_zones(caller: &Caller) -> Result<Vec<String>, ServiceError> {
        let visible = visible_zone_ids(caller);
        let zones = RepositoryService::get_all_zones().await?;
        Ok(zones
            .into_iter()
            .filter(|zone| visible.as_ref().is_none_or(|ids| ids.contains(&zone.id)))
            .map(|zone| zone.name)
            .collect())
    }

    /// Records of every zone the caller may manage, restricted to the
    /// ExternalDNS-supported record types, with absolute owner names and
    /// presentation-form values.
    pub async fn list_records(caller: &Caller) -> Result<Vec<ExternalDnsRecordItem>, ServiceError> {
        let visible = visible_zone_ids(caller);
        let zones = RepositoryService::get_all_zones().await?;
        let mut items = Vec::new();

        for zone in zones
            .iter()
            .filter(|zone| visible.as_ref().is_none_or(|ids| ids.contains(&zone.id)))
        {
            let records = RepositoryService::get_records_by_zone_id(zone.id).await?;
            for record in records {
                if !apply::is_supported_record_type(&record.record_type) {
                    continue;
                }
                items.push(ExternalDnsRecordItem {
                    name: display_record_owner_name(&record.name, &zone.name)
                        .trim_end_matches('.')
                        .to_string(),
                    record_type: record.record_type.to_string(),
                    ttl: record.ttl,
                    value: presentation_rdata(&record.value, record.priority, &record.record_type),
                });
            }
        }

        // Deterministic order so an unchanged state never reads as a diff.
        items.sort_by(|a, b| {
            (&a.name, &a.record_type, &a.value).cmp(&(&b.name, &b.record_type, &b.value))
        });
        Ok(items)
    }
}
