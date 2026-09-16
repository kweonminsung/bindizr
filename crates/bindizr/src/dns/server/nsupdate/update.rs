//! Decoding an UPDATE message into the operations the service applies:
//! TSIG verification, the wire shapes RFC 2136 fixes for each section, and
//! rdata parsing. Everything that touches zone data lives in the service.

use std::net::IpAddr;

use bindizr_core::{
    config,
    dns::{
        message::{Class, Rtype},
        name::ZoneName,
        nsupdate::parser::{UpdateRequest, UpdateRr},
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
    client_ip: IpAddr,
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
        let key = authenticate_request(&request, query_data, client_ip, &mut signer).await?;

        let update = DynamicUpdate {
            zone_name,
            key,
            prerequisites: request
                .prerequisites
                .iter()
                .map(|rr| decode_prerequisite(rr, query_data))
                .collect::<Result<_, _>>()?,
            updates: request
                .updates
                .iter()
                .map(|rr| decode_update(rr, query_data))
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
/// accepted via `dns.nsupdate_allow_unsigned` (not recommended in
/// production); signed requests are always verified.
async fn authenticate_request(
    request: &UpdateRequest,
    query_data: &[u8],
    client_ip: IpAddr,
    signer: &mut Option<ResponseSigner>,
) -> Result<Option<TsigKey>, UpdateError> {
    let tsig = match &request.tsig {
        Some(tsig) => tsig,
        None => {
            // An unsigned update carries no identity a remote sender could prove.
            // A v4 client on a `::` listener arrives mapped, so canonicalize first.
            if config::bindizr_config().dns.nsupdate_allow_unsigned
                && client_ip.to_canonical().is_loopback()
            {
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
fn decode_prerequisite(rr: &UpdateRr, query_data: &[u8]) -> Result<Prerequisite, UpdateError> {
    if rr.ttl != 0 {
        return Err(UpdateError::Refused(
            "prerequisite TTL must be 0".to_string(),
        ));
    }

    let name = rr.name.clone();
    match rr.class {
        Class::ANY | Class::NONE => {
            let is_any_class = rr.class == Class::ANY;
            if !rr.rdata.is_empty() {
                return Err(UpdateError::Refused(format!(
                    "{}-class prerequisite must have empty rdata",
                    if is_any_class { "ANY" } else { "NONE" }
                )));
            }

            Ok(match (is_any_class, rr.rr_type) {
                (true, Rtype::ANY) => Prerequisite::NameInUse { name },
                (false, Rtype::ANY) => Prerequisite::NameNotInUse { name },
                (true, rr_type) => Prerequisite::RrsetInUse {
                    name,
                    record_type: RecordType::try_from(rr_type)?,
                },
                (false, rr_type) => Prerequisite::RrsetNotInUse {
                    name,
                    record_type: RecordType::try_from(rr_type)?,
                },
            })
        }
        Class::IN => {
            if rr.rr_type == Rtype::ANY || rr.rdata.is_empty() {
                return Err(UpdateError::Refused(
                    "IN-class prerequisite must specify record type and rdata".to_string(),
                ));
            }

            let (record_type, value, priority) = rr.to_record_value(query_data)?;
            Ok(Prerequisite::RrInUse {
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
fn decode_update(rr: &UpdateRr, query_data: &[u8]) -> Result<UpdateOp, UpdateError> {
    let name = rr.name.clone();
    match rr.class {
        Class::IN => {
            let (record_type, value, priority) = rr.to_record_value(query_data)?;
            if rr.ttl > i32::MAX as u32 {
                return Err(UpdateError::Refused(format!(
                    "TTL value {} exceeds maximum allowed value ({})",
                    rr.ttl,
                    i32::MAX
                )));
            }
            Ok(UpdateOp::AddRr {
                name,
                record_type,
                value,
                ttl: rr.ttl as i32,
                priority,
            })
        }
        Class::ANY => {
            validate_delete_shape(rr, true)?;
            Ok(UpdateOp::DeleteRrset {
                name,
                record_type: (rr.rr_type != Rtype::ANY)
                    .then(|| RecordType::try_from(rr.rr_type))
                    .transpose()?,
            })
        }
        Class::NONE => {
            validate_delete_shape(rr, false)?;
            let (record_type, value, priority) = rr.to_record_value(query_data)?;
            Ok(UpdateOp::DeleteRr {
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
fn validate_delete_shape(rr: &UpdateRr, is_rrset_delete: bool) -> Result<(), UpdateError> {
    if rr.ttl != 0 {
        return Err(UpdateError::Refused(
            "delete update TTL must be 0".to_string(),
        ));
    }

    if is_rrset_delete {
        if !rr.rdata.is_empty() {
            return Err(UpdateError::Refused(
                "ANY-class delete must have empty rdata".to_string(),
            ));
        }
    } else {
        if rr.rr_type == Rtype::ANY {
            return Err(UpdateError::Refused(
                "NONE-class delete must specify record type".to_string(),
            ));
        }

        if rr.rdata.is_empty() {
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
        nsupdate::parser::UpdateRr,
    };

    use super::{UpdateError, validate_delete_shape};

    /// Verify that an ANY-class deletion accepts zero TTL and empty RDATA.
    #[test]
    fn validate_delete_shape_accepts_any_class_rrset_delete() {
        let rr = update_rr(Rtype::A, Class::ANY, 0, Vec::new());

        validate_delete_shape(&rr, true).unwrap();
    }

    /// Verify that a NONE-class deletion accepts a specific record's RDATA.
    #[test]
    fn validate_delete_shape_accepts_none_class_exact_delete() {
        let rr = update_rr(Rtype::A, Class::NONE, 0, vec![192, 0, 2, 1]);

        validate_delete_shape(&rr, false).unwrap();
    }

    /// Verify that deletions reject a nonzero TTL.
    #[test]
    fn validate_delete_shape_rejects_delete_with_nonzero_ttl() {
        let rr = update_rr(Rtype::A, Class::ANY, 60, Vec::new());
        let err = validate_delete_shape(&rr, true).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Verify that an ANY-class deletion rejects RDATA.
    #[test]
    fn validate_delete_shape_rejects_any_class_delete_with_rdata() {
        let rr = update_rr(Rtype::A, Class::ANY, 0, vec![192, 0, 2, 1]);
        let err = validate_delete_shape(&rr, true).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Verify that a NONE-class deletion requires RDATA.
    #[test]
    fn validate_delete_shape_rejects_none_class_delete_without_rdata() {
        let rr = update_rr(Rtype::A, Class::NONE, 0, Vec::new());
        let err = validate_delete_shape(&rr, false).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Verify that a NONE-class deletion requires a specific record type.
    #[test]
    fn validate_delete_shape_rejects_none_class_delete_with_type_any() {
        let rr = update_rr(Rtype::ANY, Class::NONE, 0, vec![192, 0, 2, 1]);
        let err = validate_delete_shape(&rr, false).unwrap_err();

        assert!(matches!(err, UpdateError::Refused(_)));
    }

    /// Build a dynamic update record with the requested wire fields.
    fn update_rr(rr_type: Rtype, class: Class, ttl: u32, rdata: Vec<u8>) -> UpdateRr {
        UpdateRr {
            name: "www.example.com.".to_string(),
            rr_type,
            class,
            ttl,
            rdata,
            rdata_start: 0,
        }
    }
}
