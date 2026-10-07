//! Decoding an UPDATE message into the operations the service applies:
//! TSIG verification, the wire shapes RFC 2136 fixes for each section, and
//! rdata parsing. Everything that touches zone data lives in the service.

use bindizr_core::{
    dns::{
        Ttl,
        message::{Class, Rtype},
        name::ZoneName,
        nsupdate::parser::{DeleteShapeError, ParseUpdateError, UpdateRecord, UpdateRequest},
        tsig::{ResponseSigner, TsigError},
    },
    model::{record::RecordType, tsig_key::TsigKey},
};
use bindizr_service::{
    dynamic_update::{self, DynamicUpdate, DynamicUpdateError, Prerequisite, UpdateOperation},
    tsig_key,
};
use thiserror::Error;

use crate::dns::server::DnsContext;

#[derive(Debug, Error)]
pub(crate) enum UpdateError {
    /// A section breaks the shapes RFC 2136, Sections 3.2.1 and 3.4.1 fix.
    #[error("{0}")]
    FormErr(String),
    #[error("{0}")]
    Refused(String),
    /// TSIG validation failed. Carries the complete NOTAUTH wire response,
    /// built during validation because it must echo (or sign against) the
    /// request's TSIG record (RFC 8945, Sections 5.2–5.3).
    #[error("{msg}")]
    TsigFailed { msg: String, response: Vec<u8> },
    #[error("{0}")]
    YxDomain(String),
    #[error("{0}")]
    YxRrset(String),
    #[error("{0}")]
    NxDomain(String),
    #[error("{0}")]
    NxRrset(String),
    #[error("{0}")]
    NotAuth(String),
    #[error("{0}")]
    NotZone(String),
    /// A fault of the server's own, answered SERVFAIL; the failure stays
    /// beneath it.
    #[error("{message}: {source}")]
    Internal {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// A deletion of the wrong shape is a FORMERR (RFC 2136, Section 3.4.1).
impl From<DeleteShapeError> for UpdateError {
    /// Report the shape the record lacked.
    fn from(err: DeleteShapeError) -> Self {
        UpdateError::FormErr(err.to_string())
    }
}

/// Rdata that does not decode as its type, or a type no update may carry,
/// is a FORMERR (RFC 2136, Section 3.4.1).
impl From<ParseUpdateError> for UpdateError {
    /// Report what did not decode.
    fn from(err: ParseUpdateError) -> Self {
        UpdateError::FormErr(err.to_string())
    }
}

impl From<TsigError> for UpdateError {
    /// Convert a failure into a dynamic update response error.
    fn from(err: TsigError) -> Self {
        match err {
            TsigError::Malformed(_) => UpdateError::Refused(err.to_string()),
            TsigError::Rejected { rcode, response } => UpdateError::TsigFailed {
                msg: format!("TSIG validation failed: {}", rcode),
                response,
            },
            other => UpdateError::Internal {
                message: "TSIG verification failed".to_string(),
                source: Box::new(other),
            },
        }
    }
}

impl From<DynamicUpdateError> for UpdateError {
    /// Convert a failure into a dynamic update response error.
    fn from(err: DynamicUpdateError) -> Self {
        match err {
            DynamicUpdateError::Refused(msg) => UpdateError::Refused(msg),
            DynamicUpdateError::YxDomain(msg) => UpdateError::YxDomain(msg),
            DynamicUpdateError::YxRrset(msg) => UpdateError::YxRrset(msg),
            DynamicUpdateError::NxDomain(msg) => UpdateError::NxDomain(msg),
            DynamicUpdateError::NxRrset(msg) => UpdateError::NxRrset(msg),
            DynamicUpdateError::NotAuth(msg) => UpdateError::NotAuth(msg),
            DynamicUpdateError::NotZone(msg) => UpdateError::NotZone(msg),
            DynamicUpdateError::Internal(err) => UpdateError::Internal {
                message: "failed to apply the update".to_string(),
                source: Box::new(err),
            },
        }
    }
}

/// Apply an UPDATE request, returning whether zone data actually changed. The
/// returned signer is `Some` once the request's TSIG was validated, so the
/// response — success or failure — can be signed.
pub(crate) async fn apply_update(
    dns_cx: &DnsContext,
    request: UpdateRequest,
    query_data: &[u8],
) -> (Result<bool, UpdateError>, Option<ResponseSigner>) {
    let mut signer = None;
    let result = async {
        // The parser renders the zone absolute; decoding it into labels here
        // leaves no string test to decide where its root dot ends the name. A
        // name no zone can carry is not served here (RFC 2136, Section 3.1.2).
        if request.zone_name == "." {
            return Err(UpdateError::NotAuth(
                "the root zone is not served here".to_string(),
            ));
        }
        let zone_name = ZoneName::parse(&request.zone_name).map_err(|e| {
            UpdateError::NotAuth(format!("'{}' is not a zone name: {}", request.zone_name, e))
        })?;

        // Authenticate before anything zone-specific: keys are zone-independent,
        // and this lets even NOTAUTH/FORMERR/REFUSED responses be signed.
        let key = authenticate_request(dns_cx, &request, query_data, &mut signer).await?;

        let update = DynamicUpdate {
            zone_name,
            key,
            prerequisites: request
                .prerequisites
                .iter()
                .map(|record| decode_prerequisite(record, query_data))
                .collect::<Result<_, _>>()?,
            updates: request
                .updates
                .iter()
                .map(|record| decode_update(record, query_data))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect(),
        };

        let changed = dynamic_update::apply(dns_cx.daemon(), update).await?;
        Ok(changed)
    }
    .await;
    (result, signer)
}

/// Verify TSIG and retain its response signer, or return `None` for an allowed unsigned update.
/// Disabling `dns.nsupdate.tsig_required` never bypasses verification of signed requests.
async fn authenticate_request(
    dns_cx: &DnsContext,
    request: &UpdateRequest,
    query_data: &[u8],
    signer: &mut Option<ResponseSigner>,
) -> Result<Option<TsigKey>, UpdateError> {
    let cx = dns_cx.daemon();
    let tsig = match &request.tsig {
        Some(tsig) => tsig,
        None => {
            // An unsigned update carries no identity, so this admits every
            // client that reaches the listener — the same trade
            // `api.authentication_required = false` makes for the API.
            if !cx.config().dns.nsupdate.tsig_required {
                return Ok(None);
            }
            return Err(UpdateError::Refused(
                "unsigned NSUPDATE refused: no TSIG record present".to_string(),
            ));
        }
    };

    let (key, verified) = verify_signer(dns_cx, &tsig.name, query_data).await?;
    *signer = Some(verified);
    Ok(key)
}

/// Verify the request's TSIG under the key `key_name` names and return that
/// key with the context that signs the response.
pub(crate) async fn verify_signer(
    dns_cx: &DnsContext,
    key_name: &str,
    query_data: &[u8],
) -> Result<(Option<TsigKey>, ResponseSigner), UpdateError> {
    let key = tsig_key::find_by_wire_name(dns_cx.daemon(), key_name)
        .await
        .map_err(|e| UpdateError::Internal {
            message: "failed to load TSIG key".to_string(),
            source: Box::new(e),
        })?;

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let domain_key = key.as_ref().map(TsigKey::to_domain_key).transpose()?;
    let signer = bindizr_core::dns::tsig::verify_tsig(query_data, domain_key)?;
    Ok((key, signer))
}

/// One prerequisite record, its shape held to RFC 2136, Section 3.2.1 (TTL 0,
/// rdata only in the zone class); a type bindizr never stores keeps its
/// meaning, since its record set can never exist.
fn decode_prerequisite(
    record: &UpdateRecord,
    query_data: &[u8],
) -> Result<Prerequisite, UpdateError> {
    if record.ttl != 0 {
        return Err(UpdateError::FormErr(
            "prerequisite TTL must be 0".to_string(),
        ));
    }

    let name = record.name.clone();
    match record.class {
        Class::ANY | Class::NONE => {
            let is_any_class = record.class == Class::ANY;
            if !record.rdata.is_empty() {
                return Err(UpdateError::FormErr(format!(
                    "{}-class prerequisite must have empty rdata",
                    if is_any_class { "ANY" } else { "NONE" }
                )));
            }

            Ok(match (is_any_class, record.record_type) {
                (true, Rtype::ANY) => Prerequisite::NameInUse { name },
                (false, Rtype::ANY) => Prerequisite::NameNotInUse { name },
                (true, record_type) => match RecordType::try_from(record_type) {
                    Ok(record_type) => Prerequisite::RecordSetInUse { name, record_type },
                    Err(_) => Prerequisite::UnstoredTypeInUse { name, record_type },
                },
                (false, record_type) => match RecordType::try_from(record_type) {
                    Ok(record_type) => Prerequisite::RecordSetNotInUse { name, record_type },
                    Err(_) => Prerequisite::UnstoredTypeNotInUse { name, record_type },
                },
            })
        }
        Class::IN => {
            if record.record_type == Rtype::ANY || record.rdata.is_empty() {
                return Err(UpdateError::FormErr(
                    "IN-class prerequisite must specify record type and rdata".to_string(),
                ));
            }
            if RecordType::try_from(record.record_type).is_err() {
                return Ok(Prerequisite::UnstoredTypeInUse {
                    name,
                    record_type: record.record_type,
                });
            }

            let (record_type, value, priority) = record.to_record_value(query_data)?;
            Ok(Prerequisite::RecordInUse {
                name,
                record_type,
                value,
                priority,
            })
        }
        other => Err(UpdateError::FormErr(format!(
            "unsupported prerequisite class: {}",
            other
        ))),
    }
}

/// Convert one wire update record into a validated service operation, or
/// `None` for a record RFC 2136 has the server pass over: a SOA delete
/// (Sections 3.4.2.3 and 3.4.2.4) or a delete of a type bindizr never stores.
fn decode_update(
    record: &UpdateRecord,
    query_data: &[u8],
) -> Result<Option<UpdateOperation>, UpdateError> {
    let name = record.name.clone();
    match record.class {
        Class::IN => {
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            // RFC 2181, Section 8: a TTL with its top bit set reads as zero.
            let ttl = Ttl::try_from(record.ttl).unwrap_or(Ttl::from_secs(0));
            Ok(Some(UpdateOperation::AddRecord {
                name,
                record_type,
                value,
                ttl,
                priority,
            }))
        }
        Class::ANY => {
            record.validate_delete_shape()?;
            let record_type = match record.record_type {
                Rtype::ANY => None,
                Rtype::SOA => return Ok(None),
                other => match RecordType::try_from(other) {
                    Ok(record_type) => Some(record_type),
                    Err(_) => return Ok(None),
                },
            };
            Ok(Some(UpdateOperation::DeleteRecordSet { name, record_type }))
        }
        Class::NONE => {
            record.validate_delete_shape()?;
            if record.record_type == Rtype::SOA {
                return Ok(None);
            }
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            Ok(Some(UpdateOperation::DeleteRecord {
                name,
                record_type,
                value,
                priority,
            }))
        }
        class => Err(UpdateError::FormErr(format!(
            "unsupported update class: {}",
            class
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wire record of the given shape, carrying no rdata.
    fn record(class: Class, record_type: Rtype, ttl: u32, rdata: &[u8]) -> UpdateRecord {
        UpdateRecord {
            name: "host.example.com.".to_string(),
            record_type,
            class,
            ttl,
            rdata: rdata.to_vec(),
            rdata_start: 0,
        }
    }

    /// Verify that the shapes RFC 2136, Sections 3.2.1 and 3.4.1 fix are
    /// answered FORMERR rather than REFUSED.
    #[test]
    fn malformed_sections_are_formerr() {
        let prerequisites = [
            record(Class::ANY, Rtype::ANY, 1, &[]),
            record(Class::ANY, Rtype::A, 0, &[1, 2, 3, 4]),
            record(Class::IN, Rtype::ANY, 0, &[1, 2, 3, 4]),
            record(Class::CH, Rtype::ANY, 0, &[]),
        ];
        for prerequisite in &prerequisites {
            let err = decode_prerequisite(prerequisite, &[]).unwrap_err();
            assert!(matches!(err, UpdateError::FormErr(_)), "{prerequisite:?}");
        }

        let updates = [
            record(Class::NONE, Rtype::ANY, 0, &[]),
            record(Class::ANY, Rtype::A, 0, &[1, 2, 3, 4]),
            record(Class::IN, Rtype::AXFR, 0, &[]),
            record(Class::CH, Rtype::A, 0, &[1, 2, 3, 4]),
        ];
        for update in &updates {
            let err = decode_update(update, &[]).unwrap_err();
            assert!(matches!(err, UpdateError::FormErr(_)), "{update:?}");
        }
    }

    /// Verify that a SOA delete and a delete of an unstored type are passed
    /// over, and that a TTL with its top bit set reads as zero.
    #[test]
    fn passed_over_records_and_a_high_bit_ttl() {
        assert!(
            decode_update(&record(Class::ANY, Rtype::SOA, 0, &[]), &[])
                .unwrap()
                .is_none()
        );
        assert!(
            decode_update(&record(Class::ANY, Rtype::HINFO, 0, &[]), &[])
                .unwrap()
                .is_none()
        );

        let message = [192, 0, 2, 1];
        let mut add = record(Class::IN, Rtype::A, u32::MAX, &message);
        add.rdata_start = 0;
        match decode_update(&add, &message).unwrap() {
            Some(UpdateOperation::AddRecord { ttl, .. }) => assert_eq!(ttl.as_secs(), 0),
            other => panic!("{other:?}"),
        }
    }
}
