//! Decoding an UPDATE message into the operations the service applies:
//! TSIG verification, the wire shapes RFC 2136 fixes for each section, and
//! rdata parsing. Everything that touches zone data lives in the service.

use bindizr_core::{
    config,
    dns::{
        message::{Class, Rtype},
        name::ZoneName,
        nsupdate::parser::{UpdateRecord, UpdateRequest},
        tsig::{ResponseSigner, TsigError},
    },
    model::{record::RecordType, tsig_key::TsigKey},
};
use bindizr_service::{
    dynamic_update::{
        DynamicUpdate, DynamicUpdateError, DynamicUpdateService, Prerequisite, UpdateOp,
    },
    tsig_key::TsigKeyService,
};

#[derive(Debug)]
pub(crate) enum UpdateError {
    Refused(String),
    /// TSIG validation failed. Carries the complete NOTAUTH wire response,
    /// built during validation because it must echo (or sign against) the
    /// request's TSIG record (RFC 8945, Sections 5.2–5.3).
    TsigFailed {
        msg: String,
        response: Vec<u8>,
    },
    YxDomain(String),
    YxRrset(String),
    NxDomain(String),
    NxRrset(String),
    NotZone(String),
    Internal(String),
}

/// Decoding failures from the wire parser are the client's fault.
impl From<String> for UpdateError {
    /// Convert a failure into a dynamic update response error.
    fn from(message: String) -> Self {
        UpdateError::Refused(message)
    }
}

impl From<TsigError> for UpdateError {
    /// Convert a failure into a dynamic update response error.
    fn from(err: TsigError) -> Self {
        match err {
            TsigError::Malformed(msg) => UpdateError::Refused(msg),
            TsigError::Internal(msg) => UpdateError::Internal(msg),
            TsigError::Failed { message, response } => UpdateError::TsigFailed {
                msg: message,
                response,
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
            DynamicUpdateError::Internal(msg) => UpdateError::Internal(msg),
        }
    }
}

/// Apply an UPDATE request, returning whether zone data actually changed. The
/// returned signer is `Some` once the request's TSIG was validated, so the
/// response — success or failure — can be signed.
pub(crate) async fn apply_update(
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
        let key = authenticate_request(&request, query_data, &mut signer).await?;

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

        let changed = DynamicUpdateService::apply(update).await?;
        Ok(changed)
    }
    .await;
    (result, signer)
}

/// Verify the request's TSIG signature and record the response-signing
/// context. Returns the signing key, or `None` for an unsigned request
/// accepted because `dns.nsupdate_tsig_required` is off (not recommended in
/// production); signed requests are always verified.
async fn authenticate_request(
    request: &UpdateRequest,
    query_data: &[u8],
    signer: &mut Option<ResponseSigner>,
) -> Result<Option<TsigKey>, UpdateError> {
    let tsig = match &request.tsig {
        Some(tsig) => tsig,
        None => {
            // An unsigned update carries no identity, so this admits every
            // client that reaches the listener — the same trade
            // `api.authentication_required = false` makes for the API.
            if !config::bindizr_config().dns.nsupdate_tsig_required {
                return Ok(None);
            }
            return Err(UpdateError::Refused(
                "unsigned NSUPDATE refused: no TSIG record present".to_string(),
            ));
        }
    };

    let key = TsigKeyService::find_by_wire_name(&tsig.name)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to load TSIG key: {}", e)))?;

    // An unknown key still runs validation: the empty key store makes it
    // produce the BADKEY error response.
    let domain_key = key.as_ref().map(TsigKey::to_domain_key).transpose()?;
    *signer = Some(bindizr_core::dns::tsig::verify_tsig(
        query_data, domain_key,
    )?);

    Ok(key)
}

/// One prerequisite RR, with the wire shapes of RFC 2136, Section 2.4 enforced:
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
fn decode_update(record: &UpdateRecord, query_data: &[u8]) -> Result<UpdateOp, UpdateError> {
    let name = record.name.clone();
    match record.class {
        Class::IN => {
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            if record.ttl > i32::MAX as u32 {
                return Err(UpdateError::Refused(format!(
                    "TTL value {} exceeds maximum allowed value ({})",
                    record.ttl,
                    i32::MAX
                )));
            }
            Ok(UpdateOp::AddRecord {
                name,
                record_type,
                value,
                ttl: record.ttl as i32,
                priority,
            })
        }
        Class::ANY => {
            validate_delete_shape(record, true)?;
            Ok(UpdateOp::DeleteRecordSet {
                name,
                record_type: (record.record_type != Rtype::ANY)
                    .then(|| RecordType::try_from(record.record_type))
                    .transpose()?,
            })
        }
        Class::NONE => {
            validate_delete_shape(record, false)?;
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            Ok(UpdateOp::DeleteRecord {
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

/// Validate TTL, type, and data for the selected record-deletion mode.
fn validate_delete_shape(
    record: &UpdateRecord,
    is_record_set_delete: bool,
) -> Result<(), UpdateError> {
    if record.ttl != 0 {
        return Err(UpdateError::Refused(
            "delete update TTL must be 0".to_string(),
        ));
    }

    if is_record_set_delete {
        if !record.rdata.is_empty() {
            return Err(UpdateError::Refused(
                "ANY-class delete must have empty rdata".to_string(),
            ));
        }
    } else {
        if record.record_type == Rtype::ANY {
            return Err(UpdateError::Refused(
                "NONE-class delete must specify record type".to_string(),
            ));
        }

        if record.rdata.is_empty() {
            return Err(UpdateError::Refused(
                "NONE-class delete must specify rdata".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    //! ANY-class deletions require zero TTL and empty RDATA (RFC 2136, Section 2.5.2).
    //! NONE-class deletions require zero TTL and identify a specific record through
    //! RDATA (RFC 2136, Section 2.5.4).

    use bindizr_core::dns::{
        message::{Class, Rtype},
        nsupdate::parser::UpdateRecord,
    };

    use super::{UpdateError, validate_delete_shape};

    /// Verify that an ANY-class deletion accepts zero TTL and empty RDATA.
    #[test]
    fn validate_delete_shape_accepts_any_class_record_set_delete() {
        let record = update_record(Rtype::A, Class::ANY, 0, Vec::new());

        validate_delete_shape(&record, true).unwrap();
    }

    /// Verify that a NONE-class deletion accepts a specific record's RDATA.
    #[test]
    fn validate_delete_shape_accepts_none_class_exact_delete() {
        let record = update_record(Rtype::A, Class::NONE, 0, vec![192, 0, 2, 1]);

        validate_delete_shape(&record, false).unwrap();
    }

    /// Verify that deletions reject a nonzero TTL.
    #[test]
    fn validate_delete_shape_rejects_delete_with_nonzero_ttl() {
        let record = update_record(Rtype::A, Class::ANY, 60, Vec::new());
        let err = validate_delete_shape(&record, true).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Verify that an ANY-class deletion rejects RDATA.
    #[test]
    fn validate_delete_shape_rejects_any_class_delete_with_rdata() {
        let record = update_record(Rtype::A, Class::ANY, 0, vec![192, 0, 2, 1]);
        let err = validate_delete_shape(&record, true).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Verify that a NONE-class deletion requires RDATA.
    #[test]
    fn validate_delete_shape_rejects_none_class_delete_without_rdata() {
        let record = update_record(Rtype::A, Class::NONE, 0, Vec::new());
        let err = validate_delete_shape(&record, false).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Verify that a NONE-class deletion requires a specific record type.
    #[test]
    fn validate_delete_shape_rejects_none_class_delete_with_type_any() {
        let record = update_record(Rtype::ANY, Class::NONE, 0, vec![192, 0, 2, 1]);
        let err = validate_delete_shape(&record, false).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Build a dynamic update record with the requested wire fields.
    fn update_record(record_type: Rtype, class: Class, ttl: u32, rdata: Vec<u8>) -> UpdateRecord {
        UpdateRecord {
            name: "www.example.com.".to_string(),
            record_type,
            class,
            ttl,
            rdata,
            rdata_start: 0,
        }
    }
}
