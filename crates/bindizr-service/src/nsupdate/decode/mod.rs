//! Decode complete UPDATE sections after the service has located the zone.
//! Wire records survive the prescan even when applying them will do nothing.

use bindizr_core::dns::message::{Class, Rtype};
use bindizr_core::dns::name;
use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_core::dns::nsupdate::parser::UpdateRecord;
use bindizr_core::model::dnssec_record::DnssecRecordType;
use bindizr_core::model::record::RecordType;

use crate::nsupdate::NsupdateError;
use crate::nsupdate::operation::RecordOperation;
use crate::nsupdate::plan::UpdateOperation;
use crate::nsupdate::prerequisite::Prerequisite;

/// Prescan the entire update section before selecting any operations
/// (RFC 2136, Section 3.4.1), retaining checked owners through execution.
pub(crate) fn decode_updates(
    records: &[UpdateRecord],
    zone_name: &ZoneName,
    message: &[u8],
) -> Result<Vec<UpdateOperation>, NsupdateError> {
    let checked: Vec<_> = records
        .iter()
        .map(|record| {
            let owner = parse_update_owner(&record.name, zone_name)?;
            record.validate_update_shape()?;
            validate_supported_type(record.record_type)?;
            Ok((record, owner))
        })
        .collect::<Result<_, NsupdateError>>()?;

    checked
        .into_iter()
        .filter_map(|(record, owner)| decode_update(record, owner, message).transpose())
        .collect()
}

/// Check a type in the prescan: unrecognized types are FORMERR (RFC 2136, Section 3.4.1.2).
fn validate_supported_type(rtype: Rtype) -> Result<(), NsupdateError> {
    if matches!(rtype, Rtype::SOA | Rtype::ANY)
        || RecordType::try_from(rtype).is_ok()
        || DnssecRecordType::try_from(rtype).is_ok()
    {
        Ok(())
    } else {
        Err(NsupdateError::UnsupportedType { rtype })
    }
}

/// Check and decode a prerequisite (RFC 2136, Section 3.2).
pub(crate) fn decode_prerequisite(
    record: &UpdateRecord,
    zone_name: &ZoneName,
    message: &[u8],
) -> Result<Prerequisite, NsupdateError> {
    if record.ttl.as_secs() != 0 {
        return Err(NsupdateError::FormErr {
            message: "prerequisite TTL must be 0".to_string(),
        });
    }

    // RFC 2136, Section 3.2 restricts no type; an unstored one is simply absent.
    let owner = parse_update_owner(&record.name, zone_name)?;

    match record.class {
        Class::ANY | Class::NONE => {
            let is_any_class = record.class == Class::ANY;

            if !record.rdata.is_empty() {
                return Err(NsupdateError::FormErr {
                    message: format!(
                        "{}-class prerequisite must have empty rdata",
                        if is_any_class {
                            "ANY"
                        } else {
                            "NONE"
                        }
                    ),
                });
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
                return Err(NsupdateError::FormErr {
                    message: "IN-class prerequisite must specify a record type".to_string(),
                });
            }

            Ok(Prerequisite::RecordValueMatches {
                name: owner,
                record_type: record.record_type,
                rdata: record.to_rdata(message)?,
            })
        }
        other => Err(NsupdateError::FormErr {
            message: format!("unsupported prerequisite class: {other}"),
        }),
    }
}

/// Decode updates; refuse signer-managed changes.
/// SOA deletes are ignored per RFC 2136, Sections 3.4.2.3 and 3.4.2.4.
fn decode_update(
    record: &UpdateRecord,
    owner: OwnerName,
    message: &[u8],
) -> Result<Option<UpdateOperation>, NsupdateError> {
    if DnssecRecordType::try_from(record.record_type).is_ok() {
        // Malformed RDATA must remain FORMERR, ahead of policy refusal.
        if record.class != Class::ANY {
            record.to_rdata(message)?;
        }
        return Err(NsupdateError::ManagedType {
            rtype: record.record_type,
        });
    }

    match record.class {
        Class::IN => {
            // RFC 8767, Section 4: every bit belongs to the positive TTL value.
            let ttl = record.ttl;

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
                // The prescan refused every other type, so this is its error.
                other => Some(
                    RecordType::try_from(other)
                        .map_err(|_| NsupdateError::UnsupportedType { rtype: other })?,
                ),
            };
            Ok(Some(UpdateOperation::Record(
                RecordOperation::DeleteRecordSet {
                    name: owner,
                    record_type,
                },
            )))
        }
        Class::NONE => {
            // Deleting the SOA is ignored (RFC 2136, Section 3.4.2.4).
            if record.record_type == Rtype::SOA {
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
        other => Err(NsupdateError::FormErr {
            message: format!("unsupported update class: {other}"),
        }),
    }
}

/// Parse the owner of an update record. The wire carries owners absolutely, so a name
/// outside the zone is NOTZONE rather than something to qualify.
fn parse_update_owner(name: &str, zone_name: &ZoneName) -> Result<OwnerName, NsupdateError> {
    OwnerName::parse_absolute_in_zone(name, zone_name).map_err(|source| NsupdateError::Owner {
        name: name::to_fqdn(name),
        zone_name: zone_name.clone(),
        source,
    })
}

#[cfg(test)]
mod tests;
