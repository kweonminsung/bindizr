//! ExternalDNS webhook wire protocol: the JSON shapes of `endpoint.Endpoint`,
//! `plan.Changes`, and `endpoint.DomainFilter`, validated against
//! external-dns v0.21.0, plus their conversion to the bindizr
//! `/external-dns` API shapes.

use std::collections::BTreeMap;

use bindizr_core::model::record::{EXTERNAL_DNS_RECORD_TYPES, RecordType};
use serde::{Deserialize, Serialize};

/// Exact media type external-dns compares the negotiation `Content-Type`
/// against (byte-for-byte, no media-type parsing).
pub(crate) const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

/// JSON shape of external-dns `endpoint.Endpoint` (all fields omitempty).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Endpoint {
    #[serde(default)]
    pub(crate) dns_name: String,
    #[serde(default)]
    pub(crate) targets: Vec<String>,
    #[serde(default)]
    pub(crate) record_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) set_identifier: String,
    // The Go json tag is `recordTTL`, which rename_all would render `recordTtl`.
    #[serde(default, rename = "recordTTL", skip_serializing_if = "ttl_is_unset")]
    pub(crate) record_ttl: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) provider_specific: Vec<ProviderSpecificProperty>,
}

fn ttl_is_unset(ttl: &i64) -> bool {
    *ttl == 0
}

/// JSON shape of external-dns `endpoint.ProviderSpecificProperty`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct ProviderSpecificProperty {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) value: String,
}

/// JSON shape of external-dns `plan.Changes` (`POST /records` body).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Changes {
    #[serde(default)]
    pub(crate) create: Vec<Endpoint>,
    #[serde(default)]
    pub(crate) update_old: Vec<Endpoint>,
    #[serde(default)]
    pub(crate) update_new: Vec<Endpoint>,
    #[serde(default)]
    pub(crate) delete: Vec<Endpoint>,
}

/// JSON shape of external-dns `endpoint.DomainFilter` (negotiation response).
#[derive(Debug, Default, Serialize)]
pub(crate) struct DomainFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) include: Vec<String>,
}

/// One RRset of the bindizr `/external-dns` API (snake_case, internal shape).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BindizrRrset {
    pub(crate) name: String,
    pub(crate) record_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ttl: Option<i32>,
    pub(crate) values: Vec<String>,
}

/// `POST /external-dns/changes` request body of the bindizr API.
#[derive(Debug, Default, Serialize)]
pub(crate) struct BindizrChanges {
    pub(crate) creates: Vec<BindizrRrset>,
    pub(crate) updates: Vec<BindizrRrsetUpdate>,
    pub(crate) deletes: Vec<BindizrRrset>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BindizrRrsetUpdate {
    pub(crate) old: BindizrRrset,
    pub(crate) new: BindizrRrset,
}

/// One record row of `GET /external-dns/records`.
#[derive(Debug, Deserialize)]
pub(crate) struct BindizrRecordItem {
    pub(crate) name: String,
    pub(crate) record_type: String,
    pub(crate) ttl: i32,
    pub(crate) value: String,
}

/// The endpoint's record type, if bindizr's ExternalDNS API manages it.
fn supported_record_type(record_type: &str) -> Option<RecordType> {
    let parsed = record_type.parse::<RecordType>().ok()?;
    EXTERNAL_DNS_RECORD_TYPES
        .contains(&parsed)
        .then_some(parsed)
}

/// Validate an endpoint against what the adapter supports; the message
/// becomes a permanent (4xx) error body. Mirrors the server's own validation
/// so a bad plan fails without a round trip.
pub(crate) fn validate_endpoint(endpoint: &Endpoint) -> Result<(), String> {
    if endpoint.dns_name.trim().is_empty() {
        return Err("dnsName must not be empty".to_string());
    }

    let Some(record_type) = supported_record_type(&endpoint.record_type) else {
        return Err(format!(
            "record type '{}' is not supported (supported: {})",
            endpoint.record_type,
            EXTERNAL_DNS_RECORD_TYPES
                .iter()
                .map(RecordType::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    };

    if endpoint.targets.is_empty() {
        return Err(format!("endpoint '{}' has no targets", endpoint.dns_name));
    }
    // Whitespace-only TXT content is valid; for other types it is garbage.
    let is_txt = record_type == RecordType::TXT;
    if endpoint.targets.iter().any(|t| {
        if is_txt {
            t.is_empty()
        } else {
            t.trim().is_empty()
        }
    }) {
        return Err(format!(
            "endpoint '{}' has an empty target",
            endpoint.dns_name
        ));
    }
    if record_type == RecordType::CNAME && endpoint.targets.len() > 1 {
        return Err(format!(
            "CNAME endpoint '{}' must have exactly one target",
            endpoint.dns_name
        ));
    }

    if !endpoint.set_identifier.is_empty() {
        return Err("setIdentifier is not supported by this provider".to_string());
    }

    if endpoint.record_ttl < 0 || endpoint.record_ttl > i32::MAX as i64 {
        return Err(format!("recordTTL {} is out of range", endpoint.record_ttl));
    }

    Ok(())
}

/// Convert a validated endpoint into a bindizr RRset. TXT targets pass
/// through in presentation form; the server parses and stores them.
pub(crate) fn to_bindizr_rrset(endpoint: &Endpoint) -> BindizrRrset {
    BindizrRrset {
        name: endpoint.dns_name.clone(),
        record_type: endpoint.record_type.to_ascii_uppercase(),
        ttl: (endpoint.record_ttl > 0).then_some(endpoint.record_ttl as i32),
        values: endpoint.targets.clone(),
    }
}

/// Convert a whole `plan.Changes` into one bindizr change-set request.
/// `updateOld[i]` and `updateNew[i]` pair positionally, per the plan contract.
pub(crate) fn to_bindizr_changes(changes: &Changes) -> Result<BindizrChanges, String> {
    if changes.update_old.len() != changes.update_new.len() {
        return Err(format!(
            "updateOld and updateNew must pair up ({} vs {} endpoints)",
            changes.update_old.len(),
            changes.update_new.len()
        ));
    }

    for endpoint in changes
        .create
        .iter()
        .chain(&changes.update_old)
        .chain(&changes.update_new)
        .chain(&changes.delete)
    {
        validate_endpoint(endpoint)?;
    }

    Ok(BindizrChanges {
        creates: changes.create.iter().map(to_bindizr_rrset).collect(),
        updates: changes
            .update_old
            .iter()
            .zip(&changes.update_new)
            .map(|(old, new)| BindizrRrsetUpdate {
                old: to_bindizr_rrset(old),
                new: to_bindizr_rrset(new),
            })
            .collect(),
        deletes: changes.delete.iter().map(to_bindizr_rrset).collect(),
    })
}

/// Group bindizr record rows into endpoints: one per (dnsName, recordType,
/// TTL), with targets collected in sorted order for deterministic output.
pub(crate) fn group_records_into_endpoints(records: Vec<BindizrRecordItem>) -> Vec<Endpoint> {
    let mut grouped: BTreeMap<(String, String, i32), Vec<String>> = BTreeMap::new();
    for record in records {
        grouped
            .entry((record.name, record.record_type, record.ttl))
            .or_default()
            .push(record.value);
    }

    grouped
        .into_iter()
        .map(|((dns_name, record_type, ttl), mut targets)| {
            targets.sort();
            Endpoint {
                dns_name,
                targets,
                record_type,
                record_ttl: ttl as i64,
                ..Endpoint::default()
            }
        })
        .collect()
}

/// Validate desired endpoints and convert them for `POST /adjust`;
/// validation is mirrored here so a bad plan fails without a round trip.
pub(crate) fn to_bindizr_rrsets(endpoints: &[Endpoint]) -> Result<Vec<BindizrRrset>, String> {
    for endpoint in endpoints {
        validate_endpoint(endpoint)?;
    }
    Ok(endpoints.iter().map(to_bindizr_rrset).collect())
}

/// Pair server-adjusted RRsets with the desired endpoints by position:
/// identity (dnsName, labels) stays the caller's, type/TTL/targets are the
/// server's. Dropping provider-specific properties declares them
/// unsupported.
pub(crate) fn merge_adjusted_endpoints(
    endpoints: Vec<Endpoint>,
    adjusted: Vec<BindizrRrset>,
) -> Vec<Endpoint> {
    endpoints
        .into_iter()
        .zip(adjusted)
        .map(|(mut endpoint, rrset)| {
            endpoint.provider_specific.clear();
            endpoint.record_type = rrset.record_type;
            endpoint.record_ttl = rrset.ttl.map(i64::from).unwrap_or(0);
            endpoint.targets = rrset.values;
            endpoint
        })
        .collect()
}

#[cfg(test)]
mod tests;
