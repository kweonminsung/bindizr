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
    model::{
        record::{ParseRecordTypeError, RecordType},
        tsig_key::TsigKey,
    },
};
use bindizr_service::{
    dynamic_update::{self, DynamicUpdate, DynamicUpdateError, Prerequisite, UpdateOperation},
    tsig_key,
};
use thiserror::Error;

use crate::dns::server::DnsContext;

#[derive(Debug, Error)]
pub(crate) enum UpdateError {
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

/// A deletion of the wrong shape is refused with its reason.
impl From<DeleteShapeError> for UpdateError {
    /// Refuse the update, naming what the shape lacked.
    fn from(err: DeleteShapeError) -> Self {
        UpdateError::Refused(err.to_string())
    }
}

/// A record type bindizr does not store is the client's to fix.
impl From<ParseRecordTypeError> for UpdateError {
    /// Refuse the update, naming the type.
    fn from(err: ParseRecordTypeError) -> Self {
        UpdateError::Refused(err.to_string())
    }
}

/// Decoding failures from the wire parser are the client's fault.
impl From<ParseUpdateError> for UpdateError {
    /// Refuse the update, naming what did not decode.
    fn from(err: ParseUpdateError) -> Self {
        UpdateError::Refused(err.to_string())
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
        // leaves no string test to decide where its root dot ends the name.
        if request.zone_name == "." {
            return Err(UpdateError::NotZone(
                "root zone is not supported".to_string(),
            ));
        }
        let zone_name = ZoneName::parse(&request.zone_name).map_err(|e| {
            UpdateError::NotZone(format!("'{}' is not a zone name: {}", request.zone_name, e))
        })?;

        // Authenticate before anything zone-specific: keys are zone-independent,
        // and this lets even NOTZONE/REFUSED responses be signed.
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
                .collect::<Result<_, _>>()?,
        };

        let changed = dynamic_update::apply(dns_cx.daemon(), update).await?;
        Ok(changed)
    }
    .await;
    (result, signer)
}

/// Verify TSIG and retain its response signer, or return `None` for an allowed unsigned update.
/// Disabling `nsupdate_tsig_required` never bypasses verification of signed requests.
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
            if !cx.config().dns.nsupdate_tsig_required {
                return Ok(None);
            }
            return Err(UpdateError::Refused(
                "unsigned NSUPDATE refused: no TSIG record present".to_string(),
            ));
        }
    };

    let key = tsig_key::find_by_wire_name(cx, &tsig.name)
        .await
        .map_err(|e| UpdateError::Internal {
            message: "failed to load TSIG key".to_string(),
            source: Box::new(e),
        })?;

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let domain_key = key.as_ref().map(TsigKey::to_domain_key).transpose()?;
    *signer = Some(bindizr_core::dns::tsig::verify_tsig(
        query_data, domain_key,
    )?);

    Ok(key)
}

/// One prerequisite record, with the wire shapes of RFC 2136, Section 2.4 enforced:
/// TTL is always 0, and only a CLASS IN prerequisite carries rdata.
fn decode_prerequisite(
    record: &UpdateRecord,
    query_data: &[u8],
) -> Result<Prerequisite, UpdateError> {
    if record.ttl != 0 {
        return Err(UpdateError::Refused(
            "prerequisite TTL must be 0".to_string(),
        ));
    }

    let name = record.name.clone();
    match record.class {
        Class::ANY | Class::NONE => {
            let is_any_class = record.class == Class::ANY;
            if !record.rdata.is_empty() {
                return Err(UpdateError::Refused(format!(
                    "{}-class prerequisite must have empty rdata",
                    if is_any_class { "ANY" } else { "NONE" }
                )));
            }

            Ok(match (is_any_class, record.record_type) {
                (true, Rtype::ANY) => Prerequisite::NameInUse { name },
                (false, Rtype::ANY) => Prerequisite::NameNotInUse { name },
                (true, record_type) => Prerequisite::RecordSetInUse {
                    name,
                    record_type: RecordType::try_from(record_type)?,
                },
                (false, record_type) => Prerequisite::RecordSetNotInUse {
                    name,
                    record_type: RecordType::try_from(record_type)?,
                },
            })
        }
        Class::IN => {
            if record.record_type == Rtype::ANY || record.rdata.is_empty() {
                return Err(UpdateError::Refused(
                    "IN-class prerequisite must specify record type and rdata".to_string(),
                ));
            }

            let (record_type, value, priority) = record.to_record_value(query_data)?;
            Ok(Prerequisite::RecordInUse {
                name,
                record_type,
                value,
                priority,
            })
        }
        other => Err(UpdateError::Refused(format!(
            "unsupported prerequisite class: {}",
            other
        ))),
    }
}

/// Convert one wire update record into a validated service operation.
fn decode_update(record: &UpdateRecord, query_data: &[u8]) -> Result<UpdateOperation, UpdateError> {
    let name = record.name.clone();
    match record.class {
        Class::IN => {
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            let ttl = Ttl::try_from(record.ttl).map_err(|_| {
                UpdateError::Refused(format!(
                    "TTL value {} exceeds maximum allowed value ({})",
                    record.ttl,
                    i32::MAX
                ))
            })?;
            Ok(UpdateOperation::AddRecord {
                name,
                record_type,
                value,
                ttl,
                priority,
            })
        }
        Class::ANY => {
            record.validate_delete_shape()?;
            Ok(UpdateOperation::DeleteRecordSet {
                name,
                record_type: (record.record_type != Rtype::ANY)
                    .then(|| RecordType::try_from(record.record_type))
                    .transpose()?,
            })
        }
        Class::NONE => {
            record.validate_delete_shape()?;
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            Ok(UpdateOperation::DeleteRecord {
                name,
                record_type,
                value,
                priority,
            })
        }
        class => Err(UpdateError::Refused(format!(
            "unsupported update class: {}",
            class
        ))),
    }
}
