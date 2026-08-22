//! Decoding an UPDATE message into the operations the service applies:
//! TSIG verification, the wire shapes RFC 2136 fixes for each section, and
//! rdata parsing. Everything that touches zone data lives in the service.

use bindizr_core::{config, dns::record::TxtRecordValue};
use domain::{
    base::{
        iana::{Class, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::{A, Aaaa, Mx, Srv, Txt},
};

use super::{
    auth::ResponseSigner,
    parser::{UpdateRecord, UpdateRequest, to_presentation_name},
};
use crate::{
    model::{record::RecordType, tsig_key::TsigKey},
    service::{
        dynamic_update::{
            DynamicUpdate, DynamicUpdateError, DynamicUpdateService, Prerequisite, UpdateOp,
        },
        tsig_key::TsigKeyService,
    },
};

#[derive(Debug)]
pub(super) enum UpdateError {
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

impl From<DynamicUpdateError> for UpdateError {
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
pub(super) async fn apply_update(
    request: UpdateRequest,
    query_data: &[u8],
) -> (Result<bool, UpdateError>, Option<ResponseSigner>) {
    let mut signer = None;
    let result = async {
        // The parser's presentation form appends exactly one root dot; strip
        // only it, so an escaped trailing dot inside the last label stays data.
        let zone_name = request
            .zone_name
            .strip_suffix('.')
            .unwrap_or(&request.zone_name);
        if zone_name.is_empty() {
            return Err(UpdateError::NotZone(
                "root zone is not supported".to_string(),
            ));
        }

        // Authenticate before anything zone-specific: keys are zone-independent,
        // and this lets even NOTZONE/REFUSED responses be signed.
        let key = authenticate_request(&request, query_data, &mut signer).await?;

        let update = DynamicUpdate {
            zone_name: zone_name.to_string(),
            key,
            prerequisites: decode_prerequisites(&request.prerequisites, query_data)?,
            updates: decode_updates(&request.updates, query_data)?,
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
    signer: &mut Option<ResponseSigner>,
) -> Result<Option<TsigKey>, UpdateError> {
    let tsig = match &request.tsig {
        Some(tsig) => tsig,
        None => {
            if config::bindizr_config().dns.nsupdate_allow_unsigned {
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
    let domain_key = key.as_ref().map(super::auth::to_domain_key).transpose()?;
    *signer = Some(super::auth::validate_tsig(query_data, domain_key)?);

    Ok(key)
}

fn decode_prerequisites(
    prerequisites: &[UpdateRecord],
    query_data: &[u8],
) -> Result<Vec<Prerequisite>, UpdateError> {
    prerequisites
        .iter()
        .map(|rr| decode_prerequisite(rr, query_data))
        .collect()
}

/// One prerequisite RR, with the wire shapes of RFC 2136, Section 2.4 enforced:
/// TTL is always 0, and only a CLASS IN prerequisite carries rdata.
fn decode_prerequisite(rr: &UpdateRecord, query_data: &[u8]) -> Result<Prerequisite, UpdateError> {
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
                    record_type: rr_type_to_record_type(rr_type)?,
                },
                (false, rr_type) => Prerequisite::RrsetNotInUse {
                    name,
                    record_type: rr_type_to_record_type(rr_type)?,
                },
            })
        }
        Class::IN => {
            if rr.rr_type == Rtype::ANY || rr.rdata.is_empty() {
                return Err(UpdateError::Refused(
                    "IN-class prerequisite must specify rrtype and rdata".to_string(),
                ));
            }

            let (record_type, value, priority) = rr_to_record_value(rr, query_data)?;
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

fn decode_updates(
    updates: &[UpdateRecord],
    query_data: &[u8],
) -> Result<Vec<UpdateOp>, UpdateError> {
    updates
        .iter()
        .map(|rr| decode_update(rr, query_data))
        .collect()
}

fn decode_update(rr: &UpdateRecord, query_data: &[u8]) -> Result<UpdateOp, UpdateError> {
    let name = rr.name.clone();
    match rr.class {
        Class::IN => {
            let (record_type, value, priority) = rr_to_record_value(rr, query_data)?;
            if rr.ttl > i32::MAX as u32 {
                return Err(UpdateError::Refused(format!(
                    "TTL value {} exceeds maximum allowed value ({})",
                    rr.ttl,
                    i32::MAX
                )));
            }
            Ok(UpdateOp::Add {
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
                    .then(|| rr_type_to_record_type(rr.rr_type))
                    .transpose()?,
            })
        }
        Class::NONE => {
            validate_delete_shape(rr, false)?;
            let (record_type, value, priority) = rr_to_record_value(rr, query_data)?;
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

fn validate_delete_shape(update: &UpdateRecord, is_rrset_delete: bool) -> Result<(), UpdateError> {
    if update.ttl != 0 {
        return Err(UpdateError::Refused(
            "delete update TTL must be 0".to_string(),
        ));
    }

    if is_rrset_delete {
        if !update.rdata.is_empty() {
            return Err(UpdateError::Refused(
                "ANY-class delete must have empty rdata".to_string(),
            ));
        }
    } else {
        if update.rr_type == Rtype::ANY {
            return Err(UpdateError::Refused(
                "NONE-class delete must specify rrtype".to_string(),
            ));
        }

        if update.rdata.is_empty() {
            return Err(UpdateError::Refused(
                "NONE-class delete must specify rdata".to_string(),
            ));
        }
    }

    Ok(())
}

/// Parses one rdata field in place inside the full message — so names may
/// chase compression pointers — and requires the parse to consume it exactly.
fn parse_rdata<'a, T>(
    message: &'a [u8],
    update: &UpdateRecord,
    what: &str,
    parse: impl FnOnce(&mut Parser<'a, [u8]>) -> Option<T>,
) -> Result<T, UpdateError> {
    let refused = || UpdateError::Refused(format!("invalid {} rdata", what));

    let mut parser = Parser::from_ref(message);
    parser.advance(update.rdata_start).map_err(|_| refused())?;
    let value = parse(&mut parser).ok_or_else(refused)?;

    if parser.pos() != update.rdata_start + update.rdata.len() {
        return Err(refused());
    }

    Ok(value)
}

fn rr_to_record_value(
    update: &UpdateRecord,
    message: &[u8],
) -> Result<(RecordType, String, Option<i32>), UpdateError> {
    match rr_type_to_record_type(update.rr_type)? {
        RecordType::A => {
            let data = parse_rdata(message, update, "A", |parser| A::parse(parser).ok())?;
            Ok((RecordType::A, data.addr().to_string(), None))
        }
        RecordType::AAAA => {
            let data = parse_rdata(message, update, "AAAA", |parser| Aaaa::parse(parser).ok())?;
            Ok((RecordType::AAAA, data.addr().to_string(), None))
        }
        record_type @ (RecordType::CNAME | RecordType::NS | RecordType::PTR) => {
            let name = parse_rdata(message, update, record_type.as_str(), |parser| {
                ParsedName::parse(parser).ok()
            })?;
            let value = to_presentation_name(&name).map_err(|e| {
                UpdateError::Refused(format!("invalid {} rdata: {}", record_type.as_str(), e))
            })?;
            Ok((record_type, value, None))
        }
        RecordType::TXT => {
            let data = Txt::from_octets(update.rdata.as_slice())
                .map_err(|e| UpdateError::Refused(format!("invalid TXT rdata: {}", e)))?;
            // TXT values must be valid UTF-8 (a project-wide rule), so reject
            // non-UTF-8 character-strings even though the wire allows them.
            for charstr in data.iter_charstrs() {
                if std::str::from_utf8(charstr.as_slice()).is_err() {
                    return Err(UpdateError::Refused("invalid TXT rdata".to_string()));
                }
            }
            Ok((
                RecordType::TXT,
                TxtRecordValue::from_rdata(&update.rdata).into_encoded(),
                None,
            ))
        }
        RecordType::MX => {
            let data = parse_rdata(message, update, "MX", |parser| Mx::parse(parser).ok())?;
            let host = to_presentation_name(data.exchange())
                .map_err(|e| UpdateError::Refused(format!("invalid MX rdata: {}", e)))?;
            Ok((RecordType::MX, host, Some(i32::from(data.preference()))))
        }
        RecordType::SRV => {
            let data = parse_rdata(message, update, "SRV", |parser| Srv::parse(parser).ok())?;
            let target = to_presentation_name(data.target())
                .map_err(|e| UpdateError::Refused(format!("invalid SRV rdata: {}", e)))?;
            // Priority lives in its own column, so the value holds the rest.
            Ok((
                RecordType::SRV,
                format!("{} {} {}", data.weight(), data.port(), target),
                Some(i32::from(data.priority())),
            ))
        }
        _ => Err(UpdateError::Refused(format!(
            "unsupported rr type: {}",
            update.rr_type
        ))),
    }
}

/// Record types updatable via nsupdate. SOA is excluded because it is managed
/// through the zone's own fields.
fn rr_type_to_record_type(rr_type: Rtype) -> Result<RecordType, UpdateError> {
    match rr_type {
        Rtype::A => Ok(RecordType::A),
        Rtype::NS => Ok(RecordType::NS),
        Rtype::CNAME => Ok(RecordType::CNAME),
        Rtype::PTR => Ok(RecordType::PTR),
        Rtype::MX => Ok(RecordType::MX),
        Rtype::TXT => Ok(RecordType::TXT),
        Rtype::AAAA => Ok(RecordType::AAAA),
        Rtype::SRV => Ok(RecordType::SRV),
        _ => Err(UpdateError::Refused(format!(
            "unsupported rr type: {}",
            rr_type
        ))),
    }
}

#[cfg(test)]
mod tests;
