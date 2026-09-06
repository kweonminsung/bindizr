//! ExternalDNS provider integration: authoritative zone matching and atomic
//! RRset change application behind the `/external-dns` HTTP API (consumed by
//! the bindizr-external-dns adapter). Which zones a caller may see and change
//! is decided by its token's grants, like every other endpoint.

mod apply;
mod policy;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use bindizr_db::repository::{RecordFilter, ZoneFilter};

use crate::{
    authorization::Caller,
    error::ServiceError,
    repository::RepositoryService,
    types::{ExternalDnsAdjustRequest, ExternalDnsAdjustResponse, ExternalDnsRecord},
};

/// Business logic for the ExternalDNS provider API.
pub struct ExternalDnsService;

impl ExternalDnsService {
    /// Canonicalize desired records to the form applying them would store, so
    /// the adapter's AdjustEndpoints answer cannot drift from the server's
    /// normalization. Takes no caller: it only normalizes the request's own
    /// payload.
    pub fn adjust_records(
        request: &ExternalDnsAdjustRequest,
    ) -> Result<ExternalDnsAdjustResponse, ServiceError> {
        let records = request
            .records
            .iter()
            .map(apply::adjust_rrset)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ExternalDnsAdjustResponse { records })
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
    /// ExternalDNS-supported record types: one per name and type, with absolute
    /// owner names and sorted presentation-form values.
    pub async fn list_records(caller: &Caller) -> Result<Vec<ExternalDnsRecord>, ServiceError> {
        // One query, joined against the caller's grants in SQL.
        let rows = RepositoryService::list_records_by_filter_with_zone(RecordFilter {
            scope_token_id: caller.scope_token_id(),
            ..RecordFilter::default()
        })
        .await?;

        // TTL is part of the key: one zone's rows of a name and type share it,
        // but an overlapping parent and child zone may not.
        let mut grouped: BTreeMap<(String, String, i32), Vec<String>> = BTreeMap::new();
        for row in rows {
            let record = row.record();
            if !record.record_type.is_external_dns_supported() {
                continue;
            }
            let name = policy::normalize_lookup_name(&record.name.to_fqdn(&row.zone_name))?;
            let value = record
                .record_type
                .presentation_rdata(&record.value, record.priority);
            grouped
                .entry((name, record.record_type.to_string(), record.ttl))
                .or_default()
                .push(value);
        }

        // Sorted values so an unchanged state never reads as a diff.
        Ok(grouped
            .into_iter()
            .map(|((name, record_type, ttl), mut values)| {
                values.sort();
                ExternalDnsRecord {
                    name,
                    record_type,
                    ttl: Some(ttl),
                    values,
                }
            })
            .collect())
    }
}
