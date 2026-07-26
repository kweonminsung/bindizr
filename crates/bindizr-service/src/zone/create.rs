use bindizr_core::dns::CATALOG_ZONE_NAME;
use chrono::Utc;

use super::ZoneService;
use crate::{
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    model::{
        record::{Record, RecordType},
        zone::Zone,
    },
    repository::RepositoryService,
    serial::{generate_serial, validate_initial_serial},
    types::CreateZoneRequest,
    zone::{
        DEFAULT_EXPIRE, DEFAULT_MINIMUM_TTL, DEFAULT_REFRESH, DEFAULT_RETRY,
        snapshot::save_zone_snapshot_tx,
        validation::{ResolvedSoaTimers, resolve_soa_timers, validate_create_zone_request},
    },
};

impl ZoneService {
    /// Create a new zone with an apex NS record and NOTIFY the catalog zone.
    pub async fn create(create_zone_request: &CreateZoneRequest) -> Result<Zone, ServiceError> {
        let validated = validate_create_zone_request(create_zone_request)?;
        let timers = resolve_soa_timers(
            create_zone_request,
            ResolvedSoaTimers {
                refresh: DEFAULT_REFRESH,
                retry: DEFAULT_RETRY,
                expire: DEFAULT_EXPIRE,
                minimum_ttl: DEFAULT_MINIMUM_TTL,
            },
        )?;

        // Parent/child zones are allowed; only the same normalized zone name is rejected.
        // Names are stored normalized, so an exact lookup is enough to detect a collision.
        match RepositoryService::get_zone_by_name(&validated.name).await {
            Ok(Some(_)) => {
                log_error!("Zone with name {} already exists", validated.name);
                return Err(ServiceError::zone_conflict(format!(
                    "Zone with name '{}' already exists",
                    validated.name
                )));
            }
            Ok(None) => {}
            Err(e) => {
                log_error!("Failed to check existing zone: {}", e);
                return Err(ServiceError::internal("Failed to create zone".to_string()));
            }
        };

        let serial = match create_zone_request.serial {
            Some(s) => validate_initial_serial(s)?,
            None => generate_serial(None)?,
        };

        let mut tx = RepositoryService::begin_tx("Failed to create zone").await?;

        let apply_result = async {
            let created_zone = RepositoryService::create_zone_tx(
                &mut tx,
                Zone {
                    id: 0,
                    name: validated.name.clone(),
                    primary_ns: validated.primary_ns.clone(),
                    admin_email: validated.admin_email.clone(),
                    ttl: validated.ttl,
                    serial,
                    refresh: timers.refresh,
                    retry: timers.retry,
                    expire: timers.expire,
                    minimum_ttl: timers.minimum_ttl,
                    created_at: Utc::now(),
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create zone: {}", e);
                // Keep the conflict mapped from the UNIQUE(name) backstop; it
                // covers creates that raced past the pre-check above.
                if e.code == ErrorCode::ZoneConflict {
                    e
                } else {
                    ServiceError::internal("Failed to create zone".to_string())
                }
            })?;

            // Keep zones.primary_ns aligned with at least one apex NS record in records table.
            let primary_ns_apex_record = Record {
                id: 0,
                name: "@".to_string(),
                record_type: RecordType::NS,
                value: validated.primary_ns.clone(),
                ttl: Some(validated.ttl),
                priority: None,
                zone_id: created_zone.id,
                created_at: Utc::now(),
            };

            RepositoryService::create_record_tx(&mut tx, primary_ns_apex_record)
                .await
                .map_err(|e| {
                    log_error!("Failed to create primary NS record: {}", e);
                    ServiceError::internal("Failed to create primary NS record".to_string())
                })?;

            save_zone_snapshot_tx(&mut tx, &created_zone, created_zone.serial).await?;

            Ok::<Zone, ServiceError>(created_zone)
        }
        .await;

        let created_zone =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create zone").await?;

        log_info!(
            "event=zone_create zone={} primary_ns={} serial={} zone_id={}",
            created_zone.name,
            created_zone.primary_ns,
            created_zone.serial,
            created_zone.id
        );

        // Send catalog NOTIFY so secondaries pick up the new zone
        if let Err(e) = crate::notify::send_notify_after_update(Some(CATALOG_ZONE_NAME)).await {
            log_warn!("Failed to send NOTIFY for {}: {}", CATALOG_ZONE_NAME, e);
        }

        Ok(created_zone)
    }
}
