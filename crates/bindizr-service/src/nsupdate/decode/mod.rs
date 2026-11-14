//! Decode complete UPDATE sections after the service has located the zone.
//! Wire records survive the prescan even when applying them will do nothing.

use bindizr_core::dns::Ttl;
use bindizr_core::dns::message::{Class, Rtype};
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::dns::nsupdate::parser::UpdateRecord;
use bindizr_core::model::dnssec_record::DnssecRecordType;
use bindizr_core::model::record::RecordType;

use super::{NsupdateError, Prerequisite, UpdateOperation};
use crate::nsupdate::operation::RecordOperation;

/// Prescan the entire update section before selecting any operations
/// (RFC 2136, Section 3.4.1), retaining checked owners through execution.
pub(crate) fn decode_updates(
    records: &[UpdateRecord],
    zone_name: &ZoneName,
    message: &[u8],
) -> Result<Vec<UpdateOperation>, NsupdateError> {
    let checked = records
        .iter()
        .map(|record| {
            let owner = super::parse_update_owner(&record.name, zone_name)?;
            record.validate_update_shape()?;
            validate_supported_type(record.record_type)?;
            Ok((record, owner))
        })
        .collect::<Result<Vec<_>, NsupdateError>>()?;

    checked
        .into_iter()
        .filter_map(|(record, owner)| decode_update(record, owner, message).transpose())
        .collect()
}

/// Check a type in the prescan: unrecognized types are FORMERR (RFC 2136, Section 3.4.1.2).
fn validate_supported_type(rtype: Rtype) -> Result<(), NsupdateError> {
    if matches!(rtype, Rtype::SOA | Rtype::ANY)
        || RecordType::try_from(rtype).is_ok()
        || DnssecRecordType::try_from(i32::from(rtype.to_int())).is_ok()
    {
        Ok(())
    } else {
        Err(NsupdateError::UnsupportedType(rtype))
    }
}

/// Check and decode a prerequisite (RFC 2136, Section 3.2).
pub(crate) fn decode_prerequisite(
    record: &UpdateRecord,
    zone_name: &ZoneName,
    message: &[u8],
) -> Result<Prerequisite, NsupdateError> {
    if record.ttl != 0 {
        return Err(NsupdateError::FormErr(
            "prerequisite TTL must be 0".to_string(),
        ));
    }

    // RFC 2136, Section 3.2 restricts no type; an unstored one is simply absent.
    let owner = super::parse_update_owner(&record.name, zone_name)?;

    match record.class {
        Class::ANY | Class::NONE => {
            let is_any_class = record.class == Class::ANY;

            if !record.rdata.is_empty() {
                return Err(NsupdateError::FormErr(format!(
                    "{}-class prerequisite must have empty rdata",
                    if is_any_class {
                        "ANY"
                    } else {
                        "NONE"
                    }
                )));
            }

            Ok(match (is_any_class, record.record_type) {
                (true, Rtype::ANY) => Prerequisite::NameExists { name: owner },
                (false, Rtype::ANY) => Prerequisite::NameAbsent { name: owner },
                (true, rtype) => Prerequisite::RecordSetExists {
                    name: owner,
                    record_type: rtype,
                },
                (false, rtype) => Prerequisite::RecordSetAbsent {
                    name: owner,
                    record_type: rtype,
                },
            })
        }
        Class::IN => {
            if record.record_type == Rtype::ANY {
                return Err(NsupdateError::FormErr(
                    "IN-class prerequisite must specify a record type".to_string(),
                ));
            }

            Ok(Prerequisite::RecordValueMatches {
                name: owner,
                record_type: record.record_type,
                rdata: record.to_rdata(message)?,
            })
        }
        other => Err(NsupdateError::FormErr(format!(
            "unsupported prerequisite class: {other}"
        ))),
    }
}

/// Decode updates; refuse signer-managed changes.
/// SOA deletes are ignored per RFC 2136, Sections 3.4.2.3 and 3.4.2.4.
fn decode_update(
    record: &UpdateRecord,
    owner: OwnerName,
    message: &[u8],
) -> Result<Option<UpdateOperation>, NsupdateError> {
    if DnssecRecordType::try_from(i32::from(record.record_type.to_int())).is_ok() {
        // Malformed RDATA must remain FORMERR, ahead of policy refusal.
        if record.class != Class::ANY {
            record.to_rdata(message)?;
        }
        return Err(NsupdateError::ManagedType(record.record_type));
    }

    match record.class {
        Class::IN => {
            // RFC 8767, Section 4: every bit belongs to the positive TTL value.
            let ttl = Ttl::from_secs(record.ttl);

            if record.record_type == Rtype::SOA {
                return Ok(Some(UpdateOperation::ReplaceSoa {
                    name: owner,
                    ttl,
                    value: record.to_soa_value(message)?,
                }));
            }

            let (record_type, value, priority) = record.to_record_value(message)?;

            Ok(Some(UpdateOperation::Record(RecordOperation::AddRecord {
                name: owner,
                record_type,
                value,
                ttl,
                priority,
            })))
        }
        Class::ANY => {
            let record_type = match record.record_type {
                Rtype::ANY => None,
                Rtype::SOA => return Ok(None),
                other => match RecordType::try_from(other) {
                    Ok(record_type) => Some(record_type),
                    Err(_) => return Ok(None),
                },
            };
            Ok(Some(UpdateOperation::Record(
                RecordOperation::DeleteRecordSet {
                    name: owner,
                    record_type,
                },
            )))
        }
        Class::NONE => {
            // No row can match the SOA or an unstored type (RFC 2136, Section 2.5.4).
            if RecordType::try_from(record.record_type).is_err() {
                return Ok(None);
            }

            let (record_type, value, priority) = record.to_record_value(message)?;

            Ok(Some(UpdateOperation::Record(
                RecordOperation::DeleteRecord {
                    name: owner,
                    record_type,
                    value,
                    priority,
                },
            )))
        }
        other => Err(NsupdateError::FormErr(format!(
            "unsupported update class: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests;
