use super::{
    parser::{PrerequisiteRecord, UpdateRecord},
    update::{
        CLASS_ANY, CLASS_IN, CLASS_NONE, TYPE_ANY, UpdateError, absolute_to_relative,
        normalize_owner_name, record_value_matches, rr_to_record_value, rr_type_to_record_type,
    },
};
use crate::{
    database::model::{record::Record, zone::Zone},
    service::{RepositoryTx, record::RecordService},
};

pub(super) async fn evaluate_prerequisites_tx(
    tx: &mut RepositoryTx<'_>,
    zone: &Zone,
    prerequisites: &[PrerequisiteRecord],
    query_data: &[u8],
) -> Result<(), UpdateError> {
    if prerequisites.is_empty() {
        return Ok(());
    }

    let zone_records = RecordService::list_by_zone_id_tx(tx, zone.id)
        .await
        .map_err(|e| UpdateError::Internal(format!("failed to load records: {}", e)))?;

    evaluate_prerequisites_against_records(zone, prerequisites, query_data, &zone_records)
}

fn evaluate_prerequisites_against_records(
    zone: &Zone,
    prerequisites: &[PrerequisiteRecord],
    query_data: &[u8],
    zone_records: &[Record],
) -> Result<(), UpdateError> {
    for rr in prerequisites {
        if rr.ttl != 0 {
            return Err(UpdateError::Refused(
                "prerequisite TTL must be 0".to_string(),
            ));
        }

        let owner = normalize_owner_name(&rr.name, &zone.name)?;
        let relative = absolute_to_relative(&owner, &zone.name)?;
        let owner_exists = is_owner_existing(&relative, zone_records);

        match rr.class {
            CLASS_ANY => {
                if !rr.rdata.is_empty() {
                    return Err(UpdateError::Refused(
                        "ANY-class prerequisite must have empty rdata".to_string(),
                    ));
                }

                if rr.rr_type == TYPE_ANY {
                    if !owner_exists {
                        return Err(UpdateError::NxDomain(format!(
                            "owner '{}' does not exist",
                            owner
                        )));
                    }
                } else {
                    let target_type = rr_type_to_record_type(rr.rr_type)?;
                    let rrset_exists = zone_records.iter().any(|record| {
                        record.name.eq_ignore_ascii_case(&relative)
                            && record.record_type == target_type
                    });
                    if !rrset_exists {
                        return Err(UpdateError::NxRrset(format!(
                            "RRset {} {} does not exist",
                            owner, rr.rr_type
                        )));
                    }
                }
            }
            CLASS_NONE => {
                if !rr.rdata.is_empty() {
                    return Err(UpdateError::Refused(
                        "NONE-class prerequisite must have empty rdata".to_string(),
                    ));
                }

                if rr.rr_type == TYPE_ANY {
                    if owner_exists {
                        return Err(UpdateError::YxDomain(format!("owner '{}' exists", owner)));
                    }
                } else {
                    let target_type = rr_type_to_record_type(rr.rr_type)?;
                    let rrset_exists = zone_records.iter().any(|record| {
                        record.name.eq_ignore_ascii_case(&relative)
                            && record.record_type == target_type
                    });
                    if rrset_exists {
                        return Err(UpdateError::YxRrset(format!(
                            "RRset {} {} exists",
                            owner, rr.rr_type
                        )));
                    }
                }
            }
            CLASS_IN => {
                if rr.rr_type == TYPE_ANY || rr.rdata.is_empty() {
                    return Err(UpdateError::Refused(
                        "IN-class prerequisite must specify rrtype and rdata".to_string(),
                    ));
                }

                let (target_type, target_value, target_priority) = rr_to_record_value(
                    &UpdateRecord {
                        name: rr.name.clone(),
                        rr_type: rr.rr_type,
                        class: rr.class,
                        ttl: rr.ttl,
                        rdata: rr.rdata.clone(),
                        rdata_start: rr.rdata_start,
                    },
                    query_data,
                )?;

                let exists = zone_records.iter().any(|record| {
                    record.name.eq_ignore_ascii_case(&relative)
                        && record.record_type == target_type
                        && record_value_matches(&record.record_type, &record.value, &target_value)
                        && record.priority == target_priority
                });

                if !exists {
                    return Err(UpdateError::NxRrset(format!(
                        "RR {} {} not found",
                        owner, rr.rr_type
                    )));
                }
            }
            other => {
                return Err(UpdateError::Refused(format!(
                    "unsupported prerequisite class: {}",
                    other
                )));
            }
        }
    }

    Ok(())
}

fn is_owner_existing(relative_name: &str, records: &[Record]) -> bool {
    if relative_name == "@" {
        return true;
    }

    records
        .iter()
        .any(|record| record.name.eq_ignore_ascii_case(relative_name))
}
