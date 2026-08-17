use bindizr_db::repository::LockLevel;

use super::ZoneService;
use crate::{
    error::ServiceError, log_error, log_info, model::zone::Zone, repository::RepositoryService,
    serial::generate_serial,
};

impl ZoneService {
    /// Force-increment the serial of one zone by name, or of every zone when `None`.
    pub(crate) async fn force_increment_serial(
        zone_name: Option<&str>,
    ) -> Result<Vec<Zone>, ServiceError> {
        match zone_name {
            Some(name) => {
                let zone = Self::force_increment_serial_by_name(name).await?;
                Ok(vec![zone])
            }
            None => {
                let zones = Self::list().await?;
                let mut bumped_zones = Vec::with_capacity(zones.len());

                for zone in zones {
                    // Bump each zone in its own transaction so the new serial
                    // derives from the current row and a concurrent edit to other
                    // fields is not clobbered.
                    bumped_zones
                        .push(Self::force_increment_serial_by_name(zone.name.as_str()).await?);
                }

                Ok(bumped_zones)
            }
        }
    }

    async fn force_increment_serial_by_name(zone_name: &str) -> Result<Zone, ServiceError> {
        let mut tx = RepositoryService::begin_tx("Failed to force increment zone serial").await?;

        let apply_result = async {
            let zone =
                ZoneService::get_by_name_tx(&mut tx, zone_name, LockLevel::Exclusive).await?;

            let new_serial = generate_serial(Some(zone.serial))?;
            let updated_zone = RepositoryService::update_zone_tx(
                &mut tx,
                Zone {
                    serial: new_serial,
                    ..zone
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to force increment zone serial: {}", e);
                ServiceError::internal("Failed to force increment zone serial".to_string())
            })?;

            ZoneService::save_snapshot_tx(&mut tx, &updated_zone, new_serial).await?;

            Ok::<Zone, ServiceError>(updated_zone)
        }
        .await;

        let updated_zone =
            RepositoryService::finish_tx(tx, apply_result, "Failed to force increment zone serial")
                .await?;

        log_info!(
            "event=zone_force_serial zone={} new_serial={} zone_id={}",
            updated_zone.name,
            updated_zone.serial,
            updated_zone.id
        );

        Ok(updated_zone)
    }
}
