//! Decode complete UPDATE sections after the service has located the zone.
//! Wire records survive the prescan even when applying them will do nothing.

use bindizr_core::{
    dns::{
        Ttl,
        message::{Class, Rtype},
        name::{OwnerName, ZoneName},
        nsupdate::parser::UpdateRecord,
    },
    model::{dnssec_record::DnssecRecordType, record::RecordType},
};

use super::{
    NsupdateError, Prerequisite, UpdateOperation, operation::RecordOperation, parse_update_owner,
};

/// Decode every prerequisite against the request's zone before it is evaluated.
pub(crate) fn decode_prerequisites(
    records: &[UpdateRecord],
    zone_name: &ZoneName,
    message: &[u8],
) -> Result<Vec<Prerequisite>, NsupdateError> {
    records
        .iter()
        .map(|record| decode_prerequisite(record, zone_name, message))
        .collect()
}

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
            let owner = parse_update_owner(&record.name, zone_name)?;
            record.validate_update_shape()?;
            Ok((record, owner))
        })
        .collect::<Result<Vec<_>, NsupdateError>>()?;

    checked
        .into_iter()
        .filter_map(|(record, owner)| {
            validate_supported_type(record.record_type)
                .and_then(|()| decode_update(record, owner, message))
                .transpose()
        })
        .collect()
}

/// Enforce the supported-type policy while retaining SOA, ANY, and managed DNSSEC semantics.
fn validate_supported_type(record_type: Rtype) -> Result<(), NsupdateError> {
    if matches!(record_type, Rtype::SOA | Rtype::ANY)
        || RecordType::try_from(record_type).is_ok()
        || DnssecRecordType::try_from(i32::from(record_type.to_int())).is_ok()
    {
        Ok(())
    } else {
        Err(NsupdateError::UnsupportedType(record_type))
    }
}

/// Check and decode a prerequisite (RFC 2136, Section 3.2).
fn decode_prerequisite(
    record: &UpdateRecord,
    zone_name: &ZoneName,
    query_data: &[u8],
) -> Result<Prerequisite, NsupdateError> {
    if record.ttl != 0 {
        return Err(NsupdateError::FormErr(
            "prerequisite TTL must be 0".to_string(),
        ));
    }

    let name = parse_update_owner(&record.name, zone_name)?;
    validate_supported_type(record.record_type)?;
    match record.class {
        Class::ANY | Class::NONE => {
            let is_any_class = record.class == Class::ANY;
            if !record.rdata.is_empty() {
                return Err(NsupdateError::FormErr(format!(
                    "{}-class prerequisite must have empty rdata",
                    if is_any_class { "ANY" } else { "NONE" }
                )));
            }

            Ok(match (is_any_class, record.record_type) {
                (true, Rtype::ANY) => Prerequisite::NameExists { name },
                (false, Rtype::ANY) => Prerequisite::NameAbsent { name },
                (true, record_type) => Prerequisite::RecordSetExists { name, record_type },
                (false, record_type) => Prerequisite::RecordSetAbsent { name, record_type },
            })
        }
        Class::IN => {
            if record.record_type == Rtype::ANY {
                return Err(NsupdateError::FormErr(
                    "IN-class prerequisite must specify a record type".to_string(),
                ));
            }
            Ok(Prerequisite::RecordValueMatches {
                name,
                record_type: record.record_type,
                rdata: record.to_rdata(query_data)?,
            })
        }
        other => Err(NsupdateError::FormErr(format!(
            "unsupported prerequisite class: {}",
            other
        ))),
    }
}

/// Decode a prescanned record into a service operation, or
/// `None` for a record RFC 2136 has the server pass over: a SOA delete
/// (Sections 3.4.2.3 and 3.4.2.4) or a delete of a type bindizr never stores.
fn decode_update(
    record: &UpdateRecord,
    name: OwnerName,
    query_data: &[u8],
) -> Result<Option<UpdateOperation>, NsupdateError> {
    match record.class {
        Class::IN => {
            // RFC 8767, Section 4: every bit belongs to the positive TTL value.
            let ttl = Ttl::from_secs(record.ttl);
            if record.record_type == Rtype::SOA {
                return Ok(Some(UpdateOperation::ReplaceSoa {
                    name,
                    ttl,
                    value: record.to_soa_value(query_data)?,
                }));
            }
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            Ok(Some(UpdateOperation::Record(RecordOperation::AddRecord {
                name,
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
                RecordOperation::DeleteRecordSet { name, record_type },
            )))
        }
        Class::NONE => {
            // No row can match the SOA or an unstored type (RFC 2136, Section 2.5.4).
            if RecordType::try_from(record.record_type).is_err() {
                return Ok(None);
            }
            let (record_type, value, priority) = record.to_record_value(query_data)?;
            Ok(Some(UpdateOperation::Record(
                RecordOperation::DeleteRecord {
                    name,
                    record_type,
                    value,
                    priority,
                },
            )))
        }
        class => Err(NsupdateError::FormErr(format!(
            "unsupported update class: {}",
            class
        ))),
    }
}

#[cfg(test)]
mod tests;
