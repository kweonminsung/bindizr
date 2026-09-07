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
    #[serde(default, rename = "recordTTL", skip_serializing_if = "is_ttl_unset")]
    pub(crate) record_ttl: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) provider_specific: Vec<ProviderSpecificProperty>,
}

fn is_ttl_unset(ttl: &i64) -> bool {
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
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Serialize)]
pub(crate) struct DomainFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) include: Vec<String>,
}

/// One record of the bindizr `/external-dns` API: every value of one name and
/// type (snake_case, internal shape).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BindizrRecord {
    pub(crate) name: String,
    pub(crate) record_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ttl: Option<i32>,
    pub(crate) values: Vec<String>,
}

/// `POST /external-dns/changes` request body of the bindizr API.
#[derive(Debug, Serialize)]
pub(crate) struct BindizrChanges {
    pub(crate) creates: Vec<BindizrRecord>,
    pub(crate) updates: Vec<BindizrRecordUpdate>,
    pub(crate) deletes: Vec<BindizrRecord>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BindizrRecordUpdate {
    pub(crate) old: BindizrRecord,
    pub(crate) new: BindizrRecord,
}

/// The endpoint's record type, if bindizr's ExternalDNS API manages it.
fn supported_record_type(record_type: &str) -> Option<RecordType> {
    let parsed = record_type.parse::<RecordType>().ok()?;
    parsed.is_external_dns_supported().then_some(parsed)
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
    pub(crate) fn validate(&self) -> Result<RecordType, String> {
        if self.dns_name.trim().is_empty() {
            return Err("dnsName must not be empty".to_string());
        }

        let Some(record_type) = supported_record_type(&self.record_type) else {
            return Err(format!(
                "record type '{}' is not supported (supported: {})",
                self.record_type,
                EXTERNAL_DNS_RECORD_TYPES
                    .iter()
                    .map(RecordType::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        };

        if self.targets.is_empty() {
            return Err(format!("endpoint '{}' has no targets", self.dns_name));
        }
        // Whitespace-only TXT content is valid; for other types it is garbage.
        let is_txt = record_type == RecordType::TXT;
        if self.targets.iter().any(|t| {
            if is_txt {
                t.is_empty()
            } else {
                t.trim().is_empty()
            }
        }) {
            return Err(format!("endpoint '{}' has an empty target", self.dns_name));
        }
        if record_type == RecordType::CNAME && self.targets.len() > 1 {
            return Err(format!(
                "CNAME endpoint '{}' must have exactly one target",
                self.dns_name
            ));
        }

        if !self.set_identifier.is_empty() {
            return Err("setIdentifier is not supported by this provider".to_string());
        }

        if self.record_ttl < 0 || self.record_ttl > i32::MAX as i64 {
            return Err(format!("recordTTL {} is out of range", self.record_ttl));
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
    pub(crate) fn to_bindizr(&self) -> Result<BindizrChanges, String> {
        if self.update_old.len() != self.update_new.len() {
            return Err(format!(
                "updateOld and updateNew must pair up ({} vs {} endpoints)",
                self.update_old.len(),
                self.update_new.len()
            ));
        }

        Ok(BindizrChanges {
            creates: to_bindizr_records(&self.create)?,
            updates: self
                .update_old
                .iter()
                .zip(&self.update_new)
                .map(|(old, new)| -> Result<BindizrRecordUpdate, String> {
                    Ok(BindizrRecordUpdate {
                        old: old.to_bindizr_record(old.validate()?),
                        new: new.to_bindizr_record(new.validate()?),
                    })
                })
                .collect::<Result<_, _>>()?,
            deletes: to_bindizr_records(&self.delete)?,
        })
    }
}

/// Validate endpoints and convert them into bindizr records.
pub(crate) fn to_bindizr_records(endpoints: &[Endpoint]) -> Result<Vec<BindizrRecord>, String> {
    endpoints
        .iter()
        .map(|endpoint| -> Result<BindizrRecord, String> {
            Ok(endpoint.to_bindizr_record(endpoint.validate()?))
        })
        .collect()
}

/// Pair server-adjusted records with the desired endpoints by position:
/// identity (dnsName, labels) stays the caller's, type/TTL/targets are the
/// server's. Dropping provider-specific properties declares them
/// unsupported.
pub(crate) fn merge_adjusted_endpoints(
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
