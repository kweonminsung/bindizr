//! ExternalDNS webhook wire protocol: the JSON shapes of `endpoint.Endpoint`,
//! `plan.Changes`, and `endpoint.DomainFilter`, validated against
//! external-dns v0.21.0, plus their conversion to the bindizr
//! `/external-dns` API shapes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Exact media type external-dns compares the negotiation `Content-Type`
/// against (byte-for-byte, no media-type parsing).
pub(crate) const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

/// Record types the adapter accepts; everything else is rejected explicitly.
pub(crate) const SUPPORTED_RECORD_TYPES: [&str; 4] = ["A", "AAAA", "CNAME", "TXT"];

/// JSON shape of external-dns `endpoint.Endpoint` (all fields omitempty).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Endpoint {
    #[serde(default)]
    pub dns_name: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub record_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub set_identifier: String,
    // The Go json tag is `recordTTL`, which rename_all would render `recordTtl`.
    #[serde(default, rename = "recordTTL", skip_serializing_if = "ttl_is_unset")]
    pub record_ttl: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_specific: Vec<ProviderSpecificProperty>,
}

fn ttl_is_unset(ttl: &i64) -> bool {
    *ttl == 0
}

/// JSON shape of external-dns `endpoint.ProviderSpecificProperty`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct ProviderSpecificProperty {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// JSON shape of external-dns `plan.Changes` (`POST /records` body).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Changes {
    #[serde(default)]
    pub create: Vec<Endpoint>,
    #[serde(default)]
    pub update_old: Vec<Endpoint>,
    #[serde(default)]
    pub update_new: Vec<Endpoint>,
    #[serde(default)]
    pub delete: Vec<Endpoint>,
}

/// JSON shape of external-dns `endpoint.DomainFilter` (negotiation response).
#[derive(Debug, Default, Serialize)]
pub(crate) struct DomainFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
}

/// One RRset of the bindizr `/external-dns` API (snake_case, internal shape).
#[derive(Debug, Serialize)]
pub(crate) struct BindizrRrset {
    pub name: String,
    pub record_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i32>,
    pub values: Vec<String>,
}

/// `POST /external-dns/changes` request body of the bindizr API.
#[derive(Debug, Default, Serialize)]
pub(crate) struct BindizrChanges {
    pub creates: Vec<BindizrRrset>,
    pub updates: Vec<BindizrRrsetUpdate>,
    pub deletes: Vec<BindizrRrset>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BindizrRrsetUpdate {
    pub old: BindizrRrset,
    pub new: BindizrRrset,
}

/// One record row of `GET /external-dns/records`.
#[derive(Debug, Deserialize)]
pub(crate) struct BindizrRecordItem {
    pub name: String,
    pub record_type: String,
    pub ttl: i32,
    pub value: String,
}

/// Validate an endpoint against what the adapter supports; the message
/// becomes a permanent (4xx) error body.
pub(crate) fn validate_endpoint(endpoint: &Endpoint) -> Result<(), String> {
    if endpoint.dns_name.trim().is_empty() {
        return Err("dnsName must not be empty".to_string());
    }

    let record_type = endpoint.record_type.to_ascii_uppercase();
    if !SUPPORTED_RECORD_TYPES.contains(&record_type.as_str()) {
        return Err(format!(
            "record type '{}' is not supported (supported: {})",
            endpoint.record_type,
            SUPPORTED_RECORD_TYPES.join(", ")
        ));
    }

    if endpoint.targets.is_empty() {
        return Err(format!("endpoint '{}' has no targets", endpoint.dns_name));
    }
    if endpoint.targets.iter().any(|t| t.trim().is_empty()) {
        return Err(format!(
            "endpoint '{}' has an empty target",
            endpoint.dns_name
        ));
    }
    if record_type == "CNAME" && endpoint.targets.len() > 1 {
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

/// Normalize TXT targets to the canonical quoted form `GET /records`
/// returns, so the external-dns plan never sees a spurious diff; everything
/// else is echoed unchanged.
pub(crate) fn adjust_endpoints(endpoints: Vec<Endpoint>) -> Result<Vec<Endpoint>, String> {
    endpoints
        .into_iter()
        .map(|mut endpoint| {
            validate_endpoint(&endpoint)?;
            if endpoint.record_type.eq_ignore_ascii_case("TXT") {
                endpoint.targets = endpoint
                    .targets
                    .iter()
                    .map(|target| bindizr_core::dns::txt::canonical_txt_presentation(target))
                    .collect::<Result<Vec<_>, _>>()?;
            }
            Ok(endpoint)
        })
        .collect()
}

#[cfg(test)]
mod tests;
