//! ExternalDNS webhook wire protocol: the JSON shapes of `endpoint.Endpoint`,
//! `plan.Changes`, and `endpoint.DomainFilter`, validated against
//! external-dns v0.21.0, plus their conversion to the bindizr
//! `/external-dns` API shapes.

use std::collections::BTreeMap;

use bindizr_core::model::record::{EXTERNAL_DNS_RECORD_TYPES, RecordType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact media type external-dns compares the negotiation `Content-Type`
/// against (byte-for-byte, no media-type parsing).
pub(crate) const MEDIA_TYPE: &str = "application/external.dns.webhook+json;version=1";

/// Why an endpoint is not one this provider can write; the message becomes a
/// permanent (4xx) error body.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ValidateEndpointError {
    #[error("dnsName must not be empty")]
    EmptyDnsName,
    #[error("record type '{record_type}' is not supported (supported: {})", EXTERNAL_DNS_RECORD_TYPES.iter().map(RecordType::as_str).collect::<Vec<_>>().join(", "))]
    UnsupportedRecordType { record_type: String },
    #[error("endpoint '{dns_name}' has no targets")]
    NoTargets { dns_name: String },
    #[error("endpoint '{dns_name}' has an empty target")]
    EmptyTarget { dns_name: String },
    #[error("CNAME endpoint '{dns_name}' must have exactly one target")]
    CnameTargets { dns_name: String },
    #[error("setIdentifier is not supported by this provider")]
    SetIdentifier,
    #[error("recordTTL {ttl} is out of range")]
    TtlOutOfRange { ttl: i64 },
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
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

/// Check whether an endpoint TTL uses the unset sentinel.
fn is_ttl_unset(ttl: &i64) -> bool {
    *ttl == 0
}

/// JSON shape of external-dns `endpoint.ProviderSpecificProperty`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ProviderSpecificProperty {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
}

/// JSON shape of external-dns `plan.Changes` (`POST /records` body).
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Changes {
    #[serde(default)]
    pub(crate) create: Vec<Endpoint>,
    #[serde(default)]
    update_old: Vec<Endpoint>,
    #[serde(default)]
    pub(crate) update_new: Vec<Endpoint>,
    #[serde(default)]
    pub(crate) delete: Vec<Endpoint>,
}

/// JSON shape of external-dns `endpoint.DomainFilter` (negotiation response).
#[derive(Serialize, Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DomainFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) include: Vec<String>,
}

/// One record of the bindizr `/external-dns` API: every value of one name and
/// type (snake_case, internal shape).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindizrRecord {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl: Option<i32>,
    values: Vec<String>,
}

/// `POST /external-dns/changes` request body of the bindizr API.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindizrChanges {
    creates: Vec<BindizrRecord>,
    updates: Vec<BindizrRecordUpdate>,
    deletes: Vec<BindizrRecord>,
}

/// One update of the bindizr change set: the record as stored and its
/// replacement, paired positionally from `updateOld` and `updateNew`.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindizrRecordUpdate {
    old: BindizrRecord,
    new: BindizrRecord,
}

impl Endpoint {
    /// An endpoint for one bindizr record; the server already sorts values.
    pub(crate) fn from_bindizr_record(record: BindizrRecord) -> Self {
        Endpoint {
            dns_name: record.name,
            targets: record.values,
            record_type: record.record_type,
            record_ttl: record.ttl.map(i64::from).unwrap_or(0),
            ..Endpoint::default()
        }
    }

    /// Validate against what the adapter supports, yielding the parsed record
    /// type; the message becomes a permanent (4xx) error body. Mirrors the
    /// server's own validation so a bad plan fails without a round trip.
    pub(crate) fn validate(&self) -> Result<RecordType, ValidateEndpointError> {
        if self.dns_name.trim().is_empty() {
            return Err(ValidateEndpointError::EmptyDnsName);
        }
        let Some(record_type) = RecordType::parse_external_dns_supported(&self.record_type) else {
            return Err(ValidateEndpointError::UnsupportedRecordType {
                record_type: self.record_type.clone(),
            });
        };
        if self.targets.is_empty() {
            return Err(ValidateEndpointError::NoTargets {
                dns_name: self.dns_name.clone(),
            });
        }
        // Whitespace-only TXT content is valid; for other types it is garbage.
        let is_txt = record_type == RecordType::Txt;
        if self.targets.iter().any(|t| {
            if is_txt {
                t.is_empty()
            } else {
                t.trim().is_empty()
            }
        }) {
            return Err(ValidateEndpointError::EmptyTarget {
                dns_name: self.dns_name.clone(),
            });
        }
        if record_type == RecordType::Cname && self.targets.len() > 1 {
            return Err(ValidateEndpointError::CnameTargets {
                dns_name: self.dns_name.clone(),
            });
        }
        if !self.set_identifier.is_empty() {
            return Err(ValidateEndpointError::SetIdentifier);
        }
        if self.record_ttl < 0 || self.record_ttl > i32::MAX as i64 {
            return Err(ValidateEndpointError::TtlOutOfRange {
                ttl: self.record_ttl,
            });
        }

        Ok(record_type)
    }

    /// Convert into a bindizr record under the type `validate` parsed. TXT
    /// targets pass through in presentation form; the server parses and
    /// stores them.
    pub(crate) fn to_bindizr_record(&self, record_type: RecordType) -> BindizrRecord {
        BindizrRecord {
            name: self.dns_name.clone(),
            record_type: record_type.as_str().to_string(),
            ttl: (self.record_ttl > 0).then_some(self.record_ttl as i32),
            values: self.targets.clone(),
        }
    }
}

impl Changes {
    /// Convert into one bindizr change-set request. `updateOld[i]` and
    /// `updateNew[i]` pair positionally, per the plan contract.
    pub(crate) fn to_bindizr_changes(&self) -> Result<BindizrChanges, ConvertChangesError> {
        if self.update_old.len() != self.update_new.len() {
            return Err(ConvertChangesError::UnpairedUpdates {
                old: self.update_old.len(),
                new: self.update_new.len(),
            });
        }

        Ok(BindizrChanges {
            creates: to_bindizr_records(&self.create)?,
            updates: self
                .update_old
                .iter()
                .zip(&self.update_new)
                .map(
                    |(old, new)| -> Result<BindizrRecordUpdate, ConvertChangesError> {
                        Ok(BindizrRecordUpdate {
                            old: old.to_bindizr_record(old.validate()?),
                            new: new.to_bindizr_record(new.validate()?),
                        })
                    },
                )
                .collect::<Result<_, _>>()?,
            deletes: to_bindizr_records(&self.delete)?,
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
            Ok(endpoint.to_bindizr_record(endpoint.validate()?))
        })
        .collect()
}

/// Pair server-adjusted records with the desired endpoints by position:
/// identity (dnsName, labels) stays the caller's, type/TTL/targets are the
/// server's. Dropping provider-specific properties declares them
/// unsupported.
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
            endpoint.record_ttl = record.ttl.map(i64::from).unwrap_or(0);
            endpoint.targets = record.values;
            endpoint
        })
        .collect()
}

#[cfg(test)]
mod tests;
