//! Match authoritative zones and apply atomic changes for the ExternalDNS adapter.
//! Role grants control visibility and writes through `/external-dns`.

mod apply;
mod change_set;
mod policy;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

pub use apply::apply_changes;
use bindizr_core::{dns::Ttl, model::role_grant::Action};
use bindizr_db::{record::RecordFilter, zone::ZoneFilter};

use crate::{
    Context,
    authorization::Caller,
    error::ServiceError,
    grant_pattern::pattern_domain,
    model::record::{EXTERNAL_DNS_RECORD_TYPES, RecordSetKey},
    types::{ExternalDnsAdjustRequest, ExternalDnsAdjustResponse, ExternalDnsRecord},
};

/// Rows per round trip: enough that an ordinary zone takes one or two, few
/// enough that the rows in flight stay under the group they fold into. Only
/// the read is paged; the protocol wants every endpoint in one answer.
const RECORD_READ_PAGE: u32 = 5_000;

/// Normalize desired records with the apply flow's rules for AdjustEndpoints.
/// No caller is needed: only the request's own payload is read.
pub fn adjust_records(
    request: &ExternalDnsAdjustRequest,
) -> Result<ExternalDnsAdjustResponse, ServiceError> {
    let records = request
        .records
        .iter()
        .map(change_set::adjust_record_set)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExternalDnsAdjustResponse { records })
}

/// What one ExternalDNS sync does in a domain: read ownership records, add, delete.
const SYNC_ACTIONS: [Action; 3] = [
    Action::RecordRead,
    Action::RecordCreate,
    Action::RecordDelete,
];

/// List manageable subtrees as ExternalDNS domain filters.
/// Narrow grants contribute their subtree so planning stays within apply permissions.
pub async fn list_managed_domains(
    cx: &Context,
    caller: &Caller,
) -> Result<Vec<String>, ServiceError> {
    let zones = bindizr_db::zone::list_by_filter(
        cx.db(),
        ZoneFilter {
            scope_role_id: caller.scope_role_id(),
            ..ZoneFilter::default()
        },
    )
    .await?;

    let Some(grants) = caller.grants() else {
        return Ok(zones
            .into_iter()
            .map(|zone| zone.name.to_string())
            .collect());
    };

    // Deduplicated and ordered: two grants can name one domain. A pattern
    // lacking a sync action for every type the provider writes would fail
    // every sync it reaches.
    let mut domains = BTreeSet::new();
    for zone in &zones {
        for pattern in grants.patterns_holding(zone.id, &SYNC_ACTIONS, EXTERNAL_DNS_RECORD_TYPES) {
            domains.insert(policy::normalize_lookup_name(&pattern_domain(
                pattern, &zone.name,
            ))?);
        }
    }
    Ok(domains.into_iter().collect())
}

/// Records of all zones the caller may manage, restricted to the
/// ExternalDNS-supported record types: one per name and type, with absolute
/// owner names and sorted presentation-form values.
pub async fn list_records(
    cx: &Context,
    caller: &Caller,
) -> Result<Vec<ExternalDnsRecord>, ServiceError> {
    // One zone's rows of a name and type share a TTL, but an overlapping
    // parent and child zone may not, so each record set splits by TTL.
    let mut grouped: BTreeMap<RecordSetKey, BTreeMap<Ttl, Vec<String>>> = BTreeMap::new();
    let mut offset = 0u64;

    loop {
        // Folded as they arrive, so the rows never sit beside the group
        // they build. The query's name-and-id order is total, so pages tile.
        let rows = bindizr_db::record::list_by_filter_with_zone(
            cx.db(),
            RecordFilter {
                scope_role_id: caller.scope_role_id(),
                limit: Some(RECORD_READ_PAGE),
                offset: Some(offset),
                ..RecordFilter::default()
            },
        )
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
                .entry(RecordSetKey {
                    name,
                    record_type: record.record_type,
                })
                .or_default()
                .entry(record.ttl)
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
        .flat_map(|(key, by_ttl)| {
            by_ttl.into_iter().map(move |(ttl, mut values)| {
                values.sort();
                ExternalDnsRecord {
                    name: key.name.clone(),
                    record_type: key.record_type.as_str().to_owned(),
                    ttl: Some(i32::from(ttl)),
                    values,
                }
            })
        })
        .collect())
}
