use chrono::Utc;

use super::{
    RecordService,
    bulk::{PreparedRecord, prepare_record},
    validation::{normalize_record_owner_name, validate_record_add_constraints_normalized},
};
use crate::{
    authorization::{Caller, RecordWrite},
    error::ServiceError,
    log_error, log_info, log_warn,
    model::record::{Record, RecordWithZone},
    repository::RepositoryService,
    serial::generate_serial,
    types::CreateRecordRequest,
    zone::ZoneService,
};

impl RecordService {
    /// Create a record, bumping the zone serial and recording an ADD change for IXFR.
    pub async fn create(
        create_record_request: &CreateRecordRequest,
    ) -> Result<RecordWithZone, ServiceError> {
        Self::create_for(&Caller::Global, create_record_request).await
    }

    /// Like [`Self::create`], authorizing `caller` inside the create
    /// transaction so its grants are decided against the zone this tx locked.
    pub async fn create_for(
        caller: &Caller,
        create_record_request: &CreateRecordRequest,
    ) -> Result<RecordWithZone, ServiceError> {
        let PreparedRecord {
            record_type,
            value: record_value,
            ..
        } = prepare_record(
            &create_record_request.name,
            &create_record_request.record_type,
            &create_record_request.value,
            create_record_request.ttl,
            create_record_request.priority,
        )?;

        let mut tx = RepositoryService::begin_tx("Failed to create record").await?;

        let apply_result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, &create_record_request.zone_name).await?;

            // Only records sharing the owner name can conflict, so load just
            // those instead of the whole zone.
            let normalized_owner =
                normalize_record_owner_name(&create_record_request.name, &zone.name)?;

            caller
                .authorize_record_writes_tx(
                    &mut tx,
                    &zone,
                    &[RecordWrite {
                        relative_name: normalized_owner.stored_name.as_str(),
                        record_type: Some(&record_type),
                    }],
                )
                .await?;

            let existing_records_with_name =
                match RepositoryService::get_records_by_zone_id_and_name_tx(
                    &mut tx,
                    zone.id,
                    normalized_owner.stored_name.as_str(),
                )
                .await
                {
                    Ok(records) => records,
                    Err(e) => {
                        log_error!("Failed to check existing records: {}", e);
                        return Err(ServiceError::internal(
                            "Failed to create record".to_string(),
                        ));
                    }
                };

            // Fixed at write time: a later zone TTL change will not move it.
            let ttl = create_record_request.ttl.unwrap_or(zone.ttl);

            validate_record_add_constraints_normalized(
                &existing_records_with_name,
                &normalized_owner.stored_name,
                &record_type,
                &record_value,
                ttl,
                create_record_request.priority,
                None,
            )?;

            let new_serial = generate_serial(Some(zone.serial))?;

            let created_record = Self::insert_records_with_changes_tx(
                &mut tx,
                zone.id,
                new_serial,
                &[Record {
                    id: 0,
                    name: normalized_owner.stored_name.to_string(),
                    record_type,
                    value: record_value,
                    ttl,
                    priority: create_record_request.priority,
                    zone_id: zone.id,
                    created_at: Utc::now(),
                }],
            )
            .await?
            .pop()
            .ok_or_else(|| {
                log_error!("Record insert returned no row");
                ServiceError::internal("Failed to create record".to_string())
            })?;

            ZoneService::advance_serial_tx(&mut tx, &zone, new_serial).await?;

            Ok::<(Record, String), ServiceError>((created_record, zone.name))
        }
        .await;

        let (created_record, zone_name) =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create record").await?;

        log_info!(
            "event=record_create zone={} name={} type={} ttl={} priority={} record_id={}",
            zone_name,
            create_record_request.name,
            create_record_request.record_type,
            create_record_request
                .ttl
                .map_or("null".to_string(), |v| v.to_string()),
            create_record_request
                .priority
                .map_or("null".to_string(), |v| v.to_string()),
            created_record.id
        );

        if let Err(e) = crate::notify::send_notify_after_update(Some(&zone_name)).await {
            log_warn!("Failed to send NOTIFY for zone {}: {}", zone_name, e);
        }

        Ok(RecordWithZone::new(created_record, zone_name))
    }
}
