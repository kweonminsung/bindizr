use bindizr_core::dns::name::{OwnerName, ZoneName};
use bindizr_db::repository::LockLevel;

use super::{RecordService, validation::validate_delete_constraints};
use crate::{
    authorization::{Caller, RecordWrite},
    dnssec::DnssecService,
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    repository::RepositoryService,
    serial::generate_serial,
    zone::ZoneService,
};

/// Identity of the deleted record, carried out of the transaction for logging.
struct DeletedRecord {
    zone_name: ZoneName,
    record_name: OwnerName,
    record_type: String,
    record_value: String,
    record_id: i32,
}

impl RecordService {
    /// Delete a record by id, bumping the zone serial and recording a DEL
    /// change for IXFR. `caller` is authorized inside the delete transaction,
    /// so a concurrent rename cannot outrun the check.
    pub async fn delete_by_id(caller: &Caller, record_id: i32) -> Result<(), ServiceError> {
        // Resolve zone_id with a non-locking read so the tx locks zone before
        // record (the create/bulk/import order); the reverse can deadlock.
        let zone_id = match RepositoryService::get_record_by_id(record_id).await {
            Ok(Some(record)) => record.zone_id,
            Ok(None) => {
                return Err(ServiceError::record_not_found(record_id));
            }
            Err(e) => {
                log_error!("Failed to fetch record: {}", e);
                return Err(ServiceError::internal("Failed to fetch record".to_string()));
            }
        };

        let mut tx = RepositoryService::begin_tx("Failed to delete record").await?;

        let apply_result: Result<DeletedRecord, ServiceError> = async {
            let zone =
                match RepositoryService::get_zone_by_id_tx(&mut tx, zone_id, LockLevel::Exclusive)
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
                        return Err(ServiceError::internal("Failed to fetch zone".to_string()));
                    }
                };

            let existing_record = match RepositoryService::get_record_by_id_tx(
                &mut tx,
                record_id,
                LockLevel::Exclusive,
            )
            .await
            {
                Ok(Some(record)) if record.zone_id == zone.id => record,
                Ok(Some(_)) | Ok(None) => {
                    return Err(ServiceError::record_not_found(record_id));
                }
                Err(e) => {
                    log_error!("Failed to fetch record: {}", e);
                    return Err(ServiceError::internal("Failed to fetch record".to_string()));
                }
            };

            // Invisible zones read as 404 so scoped tokens cannot probe ids.
            if !caller.zone_visible(zone.id) {
                return Err(ServiceError::record_not_found(record_id));
            }
            caller
                .authorize_record_writes_tx(
                    &mut tx,
                    &zone,
                    &[RecordWrite {
                        relative_name: existing_record.name.clone(),
                        record_type: Some(&existing_record.record_type),
                    }],
                )
                .await?;

            let new_serial = generate_serial(Some(zone.serial))?;

            validate_delete_constraints(&zone, std::slice::from_ref(&existing_record))?;

            Self::delete_records_with_changes_tx(
                &mut tx,
                zone.id,
                new_serial,
                std::slice::from_ref(&existing_record),
            )
            .await?;

            DnssecService::sign_zone_tx(&mut tx, &zone, new_serial).await?;
            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            Ok(DeletedRecord {
                zone_name: zone.name,
                record_name: existing_record.name,
                record_type: existing_record.record_type.to_string(),
                record_value: existing_record.value,
                record_id: existing_record.id,
            })
        }
        .await;

        let DeletedRecord {
            zone_name,
            record_name,
            record_type,
            record_value,
            record_id,
        } = RepositoryService::finish_tx(tx, apply_result, "Failed to delete record").await?;

        log_info!(
            "event=record_delete zone={} name={} type={} value={} record_id={}",
            zone_name,
            record_name,
            record_type,
            record_value,
            record_id
        );

        if let Err(e) = crate::notify::send_notify_after_update(Some(zone_name.as_str())).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(())
    }
}
