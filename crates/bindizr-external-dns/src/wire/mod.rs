//! ExternalDNS v0.21.0 `endpoint.Endpoint`, `plan.Changes` and `endpoint.DomainFilter`
//! JSON shapes and their conversion to bindizr's `/external-dns` API.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact media type external-dns compares the negotiation `Content-Type`
/// against (byte-for-byte, no media-type parsing).
pub(crate) const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

/// Why an endpoint is not one this provider can write; the message becomes a
/// permanent (4xx) error body. Record rules are the server's, whose 400 the
/// adapter passes through; only what the webhook shape alone shows is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ValidateEndpointError {
    #[error("setIdentifier is not supported by this provider")]
    SetIdentifier,
}

/// Why a plan could not become a bindizr change set.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConvertChangesError {
    #[error("updateOld and updateNew must pair up ({old} vs {new} endpoints)")]
    UnpairedUpdates { old: usize, new: usize },
    #[error(transparent)]
    Endpoint(#[from] ValidateEndpointError),
}

/// The upstream answer did not provide one record per endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("bindizr adjusted {records} of {endpoints} records")]
pub(crate) struct AdjustedRecordCountError {
    records: usize,
    endpoints: usize,
}

/// JSON shape of external-dns `endpoint.Endpoint` (all fields omitempty).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Endpoint {
    #[serde(default)]
    dns_name: String,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    record_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    set_identifier: String,
    // The Go json tag is `recordTTL`, which rename_all would render `recordTtl`.
    #[serde(default, rename = "recordTTL", skip_serializing_if = "is_ttl_unset")]
    record_ttl: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    provider_specific: Vec<ProviderSpecificProperty>,
}

/// Return whether an endpoint TTL uses the unset sentinel.
fn is_ttl_unset(ttl: &i64) -> bool {
    *ttl == 0
}

/// JSON shape of external-dns `endpoint.ProviderSpecificProperty`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProviderSpecificProperty {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

/// JSON shape of external-dns `plan.Changes` (`POST /records` body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct DomainFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) include: Vec<String>,
}

/// One record of the bindizr `/external-dns` API: every value of one name and
/// type (snake_case, internal shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BindizrRecord {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl: Option<i64>,
    values: Vec<String>,
}

/// `POST /external-dns/changes` request body of the bindizr API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ApplyExternalDnsChangesRequest {
    creates: Vec<BindizrRecord>,
    updates: Vec<BindizrRecordUpdate>,
    deletes: Vec<BindizrRecord>,
}

/// One update of the bindizr change set: the record as stored and its
/// replacement, paired positionally from `updateOld` and `updateNew`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BindizrRecordUpdate {
    old: BindizrRecord,
    new: BindizrRecord,
}

impl From<BindizrRecord> for Endpoint {
    /// Build an endpoint for one bindizr record; the server already sorts values.
    fn from(record: BindizrRecord) -> Self {
        Self {
            dns_name: record.name,
            targets: record.values,
            record_type: record.record_type,
            record_ttl: record.ttl.unwrap_or(0),
            ..Default::default()
        }
    }
}

impl TryFrom<&Endpoint> for BindizrRecord {
    type Error = ValidateEndpointError;

    /// Convert an endpoint to a bindizr record as sent, for the server to
    /// validate, parse and store; TTL 0 is ExternalDNS's unset. Only what the
    /// bindizr API cannot carry is refused: a `setIdentifier`, which no
    /// bindizr record has.
    fn try_from(endpoint: &Endpoint) -> Result<Self, Self::Error> {
        if !endpoint.set_identifier.is_empty() {
            return Err(ValidateEndpointError::SetIdentifier);
        }

        Ok(Self {
            name: endpoint.dns_name.clone(),
            record_type: endpoint.record_type.clone(),
            ttl: (endpoint.record_ttl != 0).then_some(endpoint.record_ttl),
            values: endpoint.targets.clone(),
        })
    }
}

impl TryFrom<&Changes> for ApplyExternalDnsChangesRequest {
    type Error = ConvertChangesError;

    /// Convert a plan into one bindizr change-set request. `updateOld[i]` and
    /// `updateNew[i]` pair positionally, per the plan contract.
    fn try_from(changes: &Changes) -> Result<Self, Self::Error> {
        if changes.update_old.len() != changes.update_new.len() {
            return Err(ConvertChangesError::UnpairedUpdates {
                old: changes.update_old.len(),
                new: changes.update_new.len(),
            });
        }

        Ok(Self {
            creates: to_bindizr_records(&changes.create)?,
            updates: changes
                .update_old
                .iter()
                .zip(&changes.update_new)
                .map(
                    |(old, new)| -> Result<BindizrRecordUpdate, ValidateEndpointError> {
                        Ok(BindizrRecordUpdate {
                            old: BindizrRecord::try_from(old)?,
                            new: BindizrRecord::try_from(new)?,
                        })
                    },
                )
                .collect::<Result<_, _>>()?,
            deletes: to_bindizr_records(&changes.delete)?,
        })
    }
}

/// Convert endpoints into bindizr records, refusing the first that cannot be one.
pub(crate) fn to_bindizr_records(
    endpoints: &[Endpoint],
) -> Result<Vec<BindizrRecord>, ValidateEndpointError> {
    endpoints.iter().map(BindizrRecord::try_from).collect()
}

/// Pair adjusted records with endpoints by position: the caller's name and
/// labels, the server's type, TTL and targets; provider-specific properties
/// are dropped as unsupported.
pub(crate) fn build_adjusted_endpoints(
    endpoints: Vec<Endpoint>,
    adjusted: Vec<BindizrRecord>,
) -> Result<Vec<Endpoint>, AdjustedRecordCountError> {
    if adjusted.len() != endpoints.len() {
        return Err(AdjustedRecordCountError {
            records: adjusted.len(),
            endpoints: endpoints.len(),
        });
    }

    Ok(endpoints
        .into_iter()
        .zip(adjusted)
        .map(|(endpoint, record)| Endpoint {
            dns_name: endpoint.dns_name,
            labels: endpoint.labels,
            ..Endpoint::from(record)
        })
        .collect())
}

#[cfg(test)]
mod tests;
