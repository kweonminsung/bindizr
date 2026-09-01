use bindizr_core::dns::CATALOG_ZONE_NAME;
use chrono::Utc;

use super::ZoneService;
use crate::{
    authorization::Caller,
    error::{ErrorCode, ServiceError},
    log_error, log_info, log_warn,
    model::zone::{DnssecDenial, Zone},
    repository::RepositoryService,
    serial::{generate_serial, validate_initial_serial},
    types::CreateZoneRequest,
    zone::{
        DEFAULT_EXPIRE, DEFAULT_MINIMUM_TTL, DEFAULT_REFRESH, DEFAULT_RETRY,
        validation::{ResolvedSoaTimers, resolve_soa_timers, validate_create_zone_request},
    },
};

impl ZoneService {
    /// Create a new zone with an apex NS record and NOTIFY the catalog zone.
    pub async fn create(
        caller: &Caller,
        create_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        caller.require_global("create zones")?;

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
        match RepositoryService::get_zone_by_name(validated.name.as_str()).await {
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
                return Err(ServiceError::internal("Failed to create zone"));
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
                    name: validated.name,
                    mname: validated.mname,
                    rname: validated.rname,
                    dnssec_denial: DnssecDenial::Nsec,
                    dnssec_signature_validity_days: None,
                    dnssec_signature_refresh_days: None,
                    dnssec_zsk_lifetime_days: None,
                    default_ttl: validated.ttl,
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
                    ServiceError::internal("Failed to create zone")
                }
            })?;

            // A new zone has no IXFR history to log against, so the apex NS row
            // goes in directly.
            RepositoryService::create_record_tx(
                &mut tx,
                created_zone.mname_record(created_zone.default_ttl),
            )
            .await
            .map_err(|e| {
                log_error!("Failed to create mname NS record: {}", e);
                ServiceError::internal("Failed to create mname NS record")
            })?;

            ZoneService::save_version_tx(&mut tx, &created_zone, created_zone.serial).await?;

            Ok::<Zone, ServiceError>(created_zone)
        }
        .await;

        let created_zone =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create zone").await?;

        log_info!(
            "event=zone_create zone={} mname={} serial={} zone_id={}",
            created_zone.name,
            created_zone.mname,
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
