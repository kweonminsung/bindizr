use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_db::repository::LockLevel;

use super::{
    RecordService,
    bulk::{PreparedRecord, prepare_record, zone_journal_changes},
    validation::{
        normalize_record_owner_name, parse_record_type,
        validate_record_update_constraints_normalized,
    },
};
use crate::{
    authorization::{Caller, RecordWrite},
    dnssec::DnssecService,
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType, RecordWithZone},
        zone::Zone,
        zone_change::ChangeOperation,
    },
    repository::RepositoryService,
    serial::generate_serial,
    types::{RecordItem, UpdateRecordPatch},
    zone::ZoneService,
};

/// The record's fields after a full request or a patch has been resolved
/// against the currently stored record. The owner is already normalized and
/// `encoded_value` already in row form.
struct ResolvedRecordUpdate {
    owner_name: OwnerName,
    record_type: RecordType,
    encoded_value: String,
    ttl: i32,
    priority: Option<i32>,
}

impl RecordService {
    /// Full replacement (HTTP PUT): every field comes from the request. The
    /// caller is authorized inside the update transaction.
    pub async fn update(
        caller: &Caller,
        record_id: i32,
        request: &RecordItem,
    ) -> Result<RecordWithZone, ServiceError> {
        Self::update_locked(caller, record_id, |zone, _existing| {
            let PreparedRecord {
                owner_name,
                record_type,
                value: encoded_value,
                ..
            } = prepare_record(
                &request.name,
                &request.record_type,
                &request.value,
                request.ttl,
                request.priority,
            )?;
            Ok(ResolvedRecordUpdate {
                owner_name: normalize_record_owner_name(&owner_name, &zone.name)?,
                record_type,
                encoded_value,
                ttl: request.ttl.unwrap_or(zone.default_ttl),
                priority: request.priority,
            })
        })
        .await
    }

    /// Partial update (CLI): omitted fields keep the stored record's value. The
    /// merge runs inside the transaction, against the row loaded there.
    pub async fn patch(
        caller: &Caller,
        record_id: i32,
        patch: &UpdateRecordPatch,
    ) -> Result<RecordWithZone, ServiceError> {
        Self::update_locked(caller, record_id, |_zone, existing| {
            let record_type = match &patch.record_type {
                Some(record_type) => parse_record_type(record_type)?,
                None => existing.record_type.clone(),
            };
            // A stored value is encoded per record type (TXT keeps raw RDATA, others
            // plain), so it can't carry across a type change — require a fresh value.
            if record_type != existing.record_type && patch.value.is_none() {
                return Err(ServiceError::invalid_input(
                    "value is required when changing a record's type".to_string(),
                ));
            }
            // Only MX/SRV carry a priority, so retyping to any other type clears it.
            let priority = if matches!(record_type, RecordType::MX | RecordType::SRV) {
                patch.priority.or(existing.priority)
            } else {
                None
            };
            let encoded_value = match &patch.value {
                Some(value) => value
                    .to_encoded_value(&record_type, priority)
                    .map_err(ServiceError::invalid_record_value)?,
                None => existing.value.clone(),
            };
            // An omitted name keeps the stored owner, which needs no reparse.
            let owner_name = match &patch.name {
                Some(name) => normalize_record_owner_name(name, &_zone.name)?,
                None => existing.name.clone(),
            };
            Ok(ResolvedRecordUpdate {
                owner_name,
                record_type,
                encoded_value,
                ttl: patch.ttl.unwrap_or(existing.ttl),
                priority,
            })
        })
        .await
    }

    /// Load the record inside the transaction, resolve the update against it,
    /// then write it, bumping the zone serial and recording DEL+ADD IXFR changes.
    async fn update_locked(
        caller: &Caller,
        record_id: i32,
        resolve: impl FnOnce(&Zone, &Record) -> Result<ResolvedRecordUpdate, ServiceError>,
    ) -> Result<RecordWithZone, ServiceError> {
        // Resolve zone_id with a non-locking read so the tx locks zone before
        // record (the create/bulk/import order); the reverse can deadlock.
        let zone_id = match RepositoryService::get_record(record_id).await {
            Ok(Some(record)) => record.zone_id,
            Ok(None) => return Err(ServiceError::record_not_found(record_id)),
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ServiceError::internal("Failed to fetch record"));
            }
        };

        let mut tx = RepositoryService::begin_tx("Failed to update record").await?;

        let apply_result = async {
            let zone = match RepositoryService::get_zone_tx(&mut tx, zone_id, LockLevel::Exclusive)
                .await
            {
                Ok(Some(zone)) => zone,
                Ok(None) => {
                    return Err(ServiceError::new(
                        ErrorCode::ZoneNotFound,
                        format!("Zone with id '{}' not found", zone_id),
                    ));
                }
                Err(e) => {
                    log_error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::internal("Failed to fetch zone"));
                }
            };

            let existing_record =
                match RepositoryService::get_record_tx(&mut tx, record_id, LockLevel::Exclusive)
                    .await
                {
                    Ok(Some(record)) if record.zone_id == zone.id => record,
                    Ok(Some(_)) | Ok(None) => {
                        return Err(ServiceError::record_not_found(record_id));
                    }
                    Err(e) => {
                        log_error!("Failed to fetch record: {}", e);
                        return Err(ServiceError::internal("Failed to fetch record"));
                    }
                };

            // Invisible zones read as 404 so scoped tokens cannot probe ids.
            if !caller.zone_visible(zone.id) {
                return Err(ServiceError::record_not_found(record_id));
            }

            let resolved = resolve(&zone, &existing_record)?;

            // An update is a delete plus an add, so both the stored identity
            // and the requested one must be granted.
            caller
                .authorize_record_writes_tx(
                    &mut tx,
                    &zone,
                    &[
                        RecordWrite {
                            relative_name: existing_record.name.clone(),
                            record_type: Some(&existing_record.record_type),
                        },
                        RecordWrite {
                            relative_name: resolved.owner_name.clone(),
                            record_type: Some(&resolved.record_type),
                        },
                    ],
                )
                .await?;
            // Only records sharing the new owner name can conflict, so load just
            // those instead of the whole zone.
            let zone_records = match RepositoryService::list_records_by_name_tx(
                &mut tx,
                zone.id,
                &resolved.owner_name,
                LockLevel::Exclusive,
            )
            .await
            {
                Ok(records) => records,
                Err(e) => {
                    log_error!("Failed to load zone records: {}", e);
                    return Err(ServiceError::internal(
                        "Failed to update record".to_string(),
                    ));
                }
            };

            let candidate_updated = Record {
                id: existing_record.id,
                name: resolved.owner_name,
                record_type: resolved.record_type,
                value: resolved.encoded_value,
                ttl: resolved.ttl,
                priority: resolved.priority,
                zone_id: zone.id,
                created_at: existing_record.created_at,
            };

            validate_record_update_constraints_normalized(
                &zone,
                &zone_records,
                &existing_record,
                &candidate_updated,
            )?;

            let new_serial = generate_serial(Some(zone.serial))?;
            let zone_name = zone.name.clone();

            let updated_record = RepositoryService::update_record_tx(&mut tx, candidate_updated)
                .await
                .map_err(|e| {
                    log_error!("Failed to update record: {}", e);
                    ServiceError::internal("Failed to update record")
                })?;

            // Record DEL(old)+ADD(new) zone changes for IXFR in one batch.
            let mut changes = zone_journal_changes(
                zone.id,
                new_serial,
                ChangeOperation::Del,
                std::slice::from_ref(&existing_record),
            );
            changes.extend(zone_journal_changes(
                zone.id,
                new_serial,
                ChangeOperation::Add,
                std::slice::from_ref(&updated_record),
            ));
            RepositoryService::create_zone_journal_tx(&mut tx, &changes)
                .await
                .map_err(|e| {
                    log_error!("Failed to create zone changes: {}", e);
                    ServiceError::internal("Failed to create zone change")
                })?;

            DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            Ok::<(Record, ZoneName), ServiceError>((updated_record, zone_name))
        }
        .await;

        let (updated_record, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to update record").await?;

        log_info!(
            "event=record_update zone={} name={} type={} ttl={} priority={} record_id={}",
            zone_name,
            updated_record.name,
            updated_record.record_type,
            updated_record.ttl,
            updated_record
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            updated_record.id
        );

        if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(RecordWithZone::new(updated_record, zone_name))
    }
}
