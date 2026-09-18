use bindizr_core::{config::bindizr_config, dns::CATALOG_ZONE_NAME};
use bindizr_db::repository::RepositoryTx;
use chrono::Utc;

use super::ZoneService;
use crate::{
    authorization::Caller,
    error::{ErrorCode, ServiceError},
    model::zone::Zone,
    repository::RepositoryService,
    serial::{generate_serial, validate_initial_serial},
    types::CreateZoneRequest,
    zone::validation::{ResolvedSoaTimers, normalize_create_zone_request, normalize_soa_timers},
};

impl ZoneService {
    /// Create a new zone with an apex NS record and NOTIFY the catalog zone.
    pub async fn create(
        caller: &Caller,
        create_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        caller.authorize_global("create zones")?;

        // Parent/child zones are allowed; only the same normalized zone name is rejected.
        // Names are stored normalized, so an exact lookup is enough to detect a collision.
        let name = normalize_create_zone_request(create_zone_request)?.name;
        match RepositoryService::get_zone_by_name(name.as_str()).await {
            Ok(Some(_)) => {
                log::error!("Zone with name {} already exists", name);
                return Err(ServiceError::zone_conflict(format!(
                    "Zone with name '{}' already exists",
                    name
                )));
            }
            Ok(None) => {}
            Err(e) => {
                log::error!("Failed to check existing zone: {}", e);
                return Err(ServiceError::internal("Failed to create zone"));
            }
        };

        let mut tx = RepositoryService::begin_tx("Failed to create zone").await?;
        let apply_result = Self::create_tx(&mut tx, caller, create_zone_request).await;
        let created_zone =
            RepositoryService::finish_tx(tx, apply_result, "Failed to create zone").await?;

        log::info!(
            "event=zone_create zone={} mname={} serial={} zone_id={}",
            created_zone.name,
            created_zone.mname,
            created_zone.serial,
            created_zone.id
        );

        // Send catalog NOTIFY so secondaries pick up the new zone
        if let Err(e) = crate::notify::send_notify_after_update(Some(CATALOG_ZONE_NAME)).await {
            log::warn!("Failed to send NOTIFY for {}: {}", CATALOG_ZONE_NAME, e);
        }

        Ok(created_zone)
    }

    /// Insert a zone, its apex NS record, and its first version on the
    /// caller's transaction. A zone import creates and fills a zone in one
    /// transaction this way, so a dry run rolls both back; [`Self::create`]
    /// adds the duplicate pre-check and the catalog NOTIFY that follows the
    /// commit. Here the UNIQUE(name) constraint is the whole duplicate check.
    pub(crate) async fn create_tx(
        tx: &mut RepositoryTx<'_>,
        caller: &Caller,
        create_zone_request: &CreateZoneRequest,
    ) -> Result<Zone, ServiceError> {
        caller.authorize_global("create zones")?;

        let validated = normalize_create_zone_request(create_zone_request)?;
        let defaults = &bindizr_config().dns.zone_defaults;
        let timers = normalize_soa_timers(
            create_zone_request,
            ResolvedSoaTimers {
                refresh: defaults.refresh,
                retry: defaults.retry,
                expire: defaults.expire,
                minimum_ttl: defaults.minimum_ttl,
            },
        )?;
        let serial = match create_zone_request.serial {
            Some(s) => validate_initial_serial(s)?,
            None => generate_serial(None)?,
        };

        let created_zone = RepositoryService::create_zone_tx(
            tx,
            Zone {
                id: 0,
                name: validated.name,
                mname: validated.mname,
                rname: validated.rname,
                dnssec_policy_id: None,
                parent_ns_addrs: None,
                enabled: true,
                description: validated.description.clone(),
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
            log::error!("Failed to create zone: {}", e);
            // Keep the conflict mapped from the UNIQUE(name) backstop; it
            // covers creates that raced past a caller's pre-check.
            if e.code == ErrorCode::ZoneConflict {
                e
            } else {
                ServiceError::internal("Failed to create zone")
            }
        })?;

        // A new zone has no IXFR history to log against, so the apex NS row
        // goes in directly.
        RepositoryService::create_record_tx(
            tx,
            created_zone.mname_record(created_zone.default_ttl),
        )
        .await
        .map_err(|e| {
            log::error!("Failed to create mname NS record: {}", e);
            ServiceError::internal("Failed to create mname NS record")
        })?;

        ZoneService::save_version_tx(
            tx,
            &created_zone,
            created_zone.serial,
            &caller.change_subject(),
        )
        .await?;

        Ok(created_zone)
    }
}
