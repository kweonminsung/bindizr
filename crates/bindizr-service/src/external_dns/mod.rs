//! ExternalDNS provider integration: authoritative zone matching and atomic
//! RRset change application behind the `/external-dns` HTTP API (consumed by
//! the bindizr-external-dns adapter). Which zones a caller may see and change
//! is decided by its token's grants, like every other endpoint.

mod apply;
mod policy;
#[cfg(test)]
mod tests;

use bindizr_db::repository::{RecordFilter, ZoneFilter};

use crate::{
    authorization::Caller,
    error::ServiceError,
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
    pub async fn list_zone_names(caller: &Caller) -> Result<Vec<String>, ServiceError> {
        let zones = RepositoryService::list_zones_by_filter(ZoneFilter {
            scope_token_id: caller.scope_token_id(),
            ..ZoneFilter::default()
        })
        .await?;
        Ok(zones
            .into_iter()
            .map(|zone| zone.name.to_string())
            .collect())
    }

    /// Records of every zone the caller may manage, restricted to the
    /// ExternalDNS-supported record types, with absolute owner names and
    /// presentation-form values.
    pub async fn list_records(caller: &Caller) -> Result<Vec<ExternalDnsRecordItem>, ServiceError> {
        // One query, joined against the caller's grants in SQL.
        let rows = RepositoryService::list_records_by_filter_with_zone(RecordFilter {
            scope_token_id: caller.scope_token_id(),
            ..RecordFilter::default()
        })
        .await?;

        let mut items = Vec::new();
        for row in rows {
            let record = row.record();
            if !record.record_type.is_external_dns_supported() {
                continue;
            }
            items.push(ExternalDnsRecordItem {
                name: record
                    .name
                    .to_fqdn(&row.zone_name)
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
