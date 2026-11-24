//! Match authoritative zones and apply atomic changes for the ExternalDNS adapter.
//! Role grants control visibility and writes through `/external-dns`.

mod apply;
mod change_set;
mod policy;

use std::collections::{BTreeMap, BTreeSet};

pub use apply::apply_changes;
use bindizr_core::dns::Ttl;
use bindizr_core::model::record::{RecordSetKey, RecordType};
use bindizr_core::model::role_grant::Action;
use bindizr_db::record::RecordFilter;
use bindizr_db::zone::ZoneFilter;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{
    AdjustExternalDnsRecordsRequest, AdjustExternalDnsRecordsResponse, ExternalDnsRecord,
};
use crate::{Context, grant_pattern};

/// The record types the ExternalDNS API manages.
pub(crate) const RECORD_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::Aaaa,
    RecordType::Cname,
    RecordType::Txt,
];

/// DB read page size; the protocol still returns all endpoints in one response.
const RECORD_READ_PAGE: u32 = 5000;

/// What one ExternalDNS sync does in a domain: read ownership records, add, delete.
const SYNC_ACTIONS: [Action; 3] = [
    Action::RecordRead,
    Action::RecordCreate,
    Action::RecordDelete,
];

/// Normalize desired records with the apply flow's rules for AdjustEndpoints.
/// No caller is needed: only the request's own payload is read.
pub fn adjust_records(
    request: &AdjustExternalDnsRecordsRequest,
) -> Result<AdjustExternalDnsRecordsResponse, ServiceError> {
    let records: Vec<_> = request
        .records
        .iter()
        .map(change_set::adjust_record_set)
        .collect::<Result<_, _>>()?;
    Ok(AdjustExternalDnsRecordsResponse { records })
}

/// List manageable subtrees as ExternalDNS domain filters.
/// Narrow grants contribute their subtree so planning stays within apply permissions.
pub async fn list_managed_domains(
    cx: &Context,
    caller: &Caller,
) -> Result<Vec<String>, ServiceError> {
    let zones = bindizr_db::zone::list_by_filter(
        cx.db(),
        &ZoneFilter {
            scope_role_id: caller.scope_role_id(),
            ..Default::default()
        },
    )
    .await?;

    let Some(grants) = caller.grants() else {
        return Ok(zones
            .into_iter()
            .map(|zone| zone.name.to_string())
            .collect());
    };

    // Each contributed subtree needs all sync actions for at least one supported type.
    let mut domains = BTreeSet::new();

    for zone in &zones {
        for pattern in grants.patterns_holding(zone.id, &SYNC_ACTIONS, RECORD_TYPES) {
            if let Some(domain) = grant_pattern::pattern_domain(pattern, &zone.name)? {
                domains.insert(domain);
            }
        }
    }

    Ok(domains.into_iter().collect())
}

/// List the records of the supported types the caller may read, grouped by
/// name/type, with absolute owners and sorted presentation values. A name
/// lists only the rows of the zone apply would write it to, so a parent's rows
/// below a child zone's apex, which no change reaches, stay out.
pub async fn list_records(
    cx: &Context,
    caller: &Caller,
) -> Result<Vec<ExternalDnsRecord>, ServiceError> {
    // Every zone, hidden ones included: a hidden child shadows a granted
    // parent here as it does in apply.
    let zones = bindizr_db::zone::list_all(cx.db()).await?;
    let zone_index = policy::ZoneIndex::new(&zones);
    // One zone answers for a name, and its rows of one type share a TTL.
    let mut grouped: BTreeMap<RecordSetKey, (Ttl, Vec<String>)> = BTreeMap::new();
    let mut offset = 0u64;

    loop {
        // Folded as they arrive, so the rows never sit beside the group
        // they build. The query's name-and-id order is total, so pages tile.
        let records_with_zones = bindizr_db::record::list_by_filter_with_zone(
            cx.db(),
            &RecordFilter {
                scope_role_id: caller.scope_role_id(),
                limit: Some(RECORD_READ_PAGE),
                offset: Some(offset),
                ..Default::default()
            },
        )
        .await?;
        let read = records_with_zones.len();
        let readable_records = caller.readable_records(
            records_with_zones
                .into_iter()
                .map(|record| (record.record.zone_id, record)),
        );

        for record_with_zone in readable_records.as_slice() {
            let record = &record_with_zone.record;

            if !RECORD_TYPES.contains(&record.record_type) {
                continue;
            }

            let name =
                policy::normalize_lookup_name(&record.name.to_fqdn(&record_with_zone.zone_name))?;

            if zone_index.find(&name).map(|(zone, _)| zone.id) != Some(record.zone_id) {
                continue;
            }

            let value = record
                .record_type
                .presentation_rdata(&record.value, record.priority);
            grouped
                .entry(RecordSetKey {
                    name,
                    record_type: record.record_type,
                })
                .or_insert_with(|| (record.ttl, Vec::new()))
                .1
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
        .map(|(key, (ttl, mut values))| {
            values.sort();
            ExternalDnsRecord {
                name: key.name,
                record_type: key.record_type.to_string(),
                ttl: Some(i64::from(ttl)),
                values,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests;
