//! ExternalDNS provider integration: authoritative zone matching and atomic
//! RRset change application behind the `/external-dns` HTTP API (consumed by
//! the bindizr-external-dns adapter). Which zones a caller may see and change
//! is decided by its token's grants, like every other endpoint.

mod apply;
mod change_set;
mod policy;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use bindizr_db::repository::{RecordFilter, ZoneFilter};

use crate::{
    authorization::Caller,
    error::ServiceError,
    grant_pattern::pattern_domain,
    repository::RepositoryService,
    types::{ExternalDnsAdjustRequest, ExternalDnsAdjustResponse, ExternalDnsRecord},
};

/// Rows per round trip: enough that an ordinary zone takes one or two, few
/// enough that the rows in flight stay under the group they fold into. Only
/// the read is paged; the protocol wants every endpoint in one answer.
const RECORD_READ_PAGE: u32 = 5_000;

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
            .map(change_set::adjust_rrset)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ExternalDnsAdjustResponse { records })
    }

    /// The names the caller may manage, as an ExternalDNS domain filter spells
    /// them: a name, and everything under it. A grant narrowed to a subtree
    /// contributes that subtree, not its zone, so ExternalDNS plans inside what
    /// the apply accepts rather than failing the whole sync on the first record
    /// outside it.
    pub async fn list_managed_domains(caller: &Caller) -> Result<Vec<String>, ServiceError> {
        let zones = RepositoryService::list_zones_by_filter(ZoneFilter {
            scope_token_id: caller.scope_token_id(),
            ..ZoneFilter::default()
        })
        .await?;

        let Some(grants) = caller.grants() else {
            return Ok(zones
                .into_iter()
                .map(|zone| zone.name.to_string())
                .collect());
        };

        // Deduplicated and ordered: two grants can name one domain. A
        // read-only grant leaves ExternalDNS nothing to do, so it stays out.
        let mut domains = BTreeSet::new();
        for zone in &zones {
            for grant in grants
                .iter()
                .filter(|grant| grant.zone_id == zone.id && grant.can_write)
            {
                domains.insert(policy::normalize_lookup_name(&pattern_domain(
                    &grant.record_name_pattern,
                    &zone.name,
                ))?);
            }
        }
        Ok(domains.into_iter().collect())
    }

    /// Records of every zone the caller may manage, restricted to the
    /// ExternalDNS-supported record types: one per name and type, with absolute
    /// owner names and sorted presentation-form values.
    pub async fn list_records(caller: &Caller) -> Result<Vec<ExternalDnsRecord>, ServiceError> {
        // TTL is part of the key: one zone's rows of a name and type share it,
        // but an overlapping parent and child zone may not.
        let mut grouped: BTreeMap<(String, String, i32), Vec<String>> = BTreeMap::new();
        let mut offset = 0u64;

        loop {
            // Folded as they arrive, so the rows never sit beside the group
            // they build. The query's name-and-id order is total, so pages tile.
            let rows = RepositoryService::list_records_by_filter_with_zone(RecordFilter {
                scope_token_id: caller.scope_token_id(),
                limit: Some(RECORD_READ_PAGE),
                offset: Some(offset),
                ..RecordFilter::default()
            })
            .await?;
            let read = rows.len();

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

            if read < RECORD_READ_PAGE as usize {
                break;
            }
            offset += read as u64;
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
