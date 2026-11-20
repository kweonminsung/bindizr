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
#[derive(Debug, Clone, PartialEq, Eq, Error)]
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

impl Endpoint {
    /// Refuse what the bindizr API cannot carry: a `setIdentifier`, which no
    /// bindizr record has. Every record rule is left to the server.
    pub(crate) fn validate(&self) -> Result<(), ValidateEndpointError> {
        if !self.set_identifier.is_empty() {
            return Err(ValidateEndpointError::SetIdentifier);
        }

        Ok(())
    }

    /// Convert the endpoint to a bindizr record as sent, for the server to
    /// validate, parse and store; TTL 0 is ExternalDNS's unset.
    pub(crate) fn to_bindizr_record(&self) -> BindizrRecord {
        BindizrRecord {
            name: self.dns_name.clone(),
            record_type: self.record_type.clone(),
            ttl: (self.record_ttl != 0).then_some(self.record_ttl),
            values: self.targets.clone(),
        }
    }
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
                    |(old, new)| -> Result<BindizrRecordUpdate, ConvertChangesError> {
                        old.validate()?;
                        new.validate()?;
                        Ok(BindizrRecordUpdate {
                            old: old.to_bindizr_record(),
                            new: new.to_bindizr_record(),
                        })
                    },
                )
                .collect::<Result<_, _>>()?,
            deletes: to_bindizr_records(&changes.delete)?,
        })
    }
}

/// Validate endpoints and convert them into bindizr records.
pub(crate) fn to_bindizr_records(
    endpoints: &[Endpoint],
) -> Result<Vec<BindizrRecord>, ConvertChangesError> {
    endpoints
        .iter()
        .map(|endpoint| -> Result<BindizrRecord, ConvertChangesError> {
            endpoint.validate()?;
            Ok(endpoint.to_bindizr_record())
        })
        .collect()
}

/// Pair adjusted records with endpoints by position, retaining caller identity
/// and server type/TTL/targets; discard unsupported provider-specific properties.
pub(crate) fn build_adjusted_endpoints(
    endpoints: Vec<Endpoint>,
    adjusted: Vec<BindizrRecord>,
) -> Vec<Endpoint> {
    endpoints
        .into_iter()
        .zip(adjusted)
        .map(|(mut endpoint, record)| {
            endpoint.provider_specific.clear();
            endpoint.record_type = record.record_type;
            endpoint.record_ttl = record.ttl.unwrap_or(0);
            endpoint.targets = record.values;
            endpoint
        })
        .collect()
}

#[cfg(test)]
mod tests;
