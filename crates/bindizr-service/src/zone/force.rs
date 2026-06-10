use super::{ZoneService, validation::normalize_zone_lookup_name};
use crate::{
    error::ServiceError, log_error, log_info, model::zone::Zone, repository::RepositoryService,
    serial::generate_serial, zone::snapshot::save_zone_snapshot_tx,
};

impl ZoneService {
    pub async fn force_increment_serial(
        zone_name: Option<&str>,
    ) -> Result<Vec<Zone>, ServiceError> {
        match zone_name {
            Some(name) => {
                let zone = Self::force_increment_zone_serial(name).await?;
                Ok(vec![zone])
            }
            None => {
                let zones = Self::list().await?;
                let mut bumped_zones = Vec::with_capacity(zones.len());

                for zone in zones {
                    bumped_zones.push(Self::force_increment_zone_serial(&zone.name).await?);
                }

                Ok(bumped_zones)
            }
        }
    }

    async fn force_increment_zone_serial(zone_name: &str) -> Result<Zone, ServiceError> {
        let lookup_name = normalize_zone_lookup_name(zone_name)?;
        let mut tx = RepositoryService::begin_tx("Failed to force increment zone serial").await?;

        let apply_result = async {
            let zone = match RepositoryService::get_zone_by_name_tx(&mut tx, &lookup_name).await {
                Ok(Some(zone)) => zone,
                Ok(None) => {
                    return Err(ServiceError::NotFound(format!(
                        "Zone with name '{}' not found",
                        zone_name
                    )));
                }
                Err(e) => {
                    log_error!("Failed to fetch zone: {}", e);
                    return Err(ServiceError::Internal(
                        "Failed to force increment zone serial".to_string(),
                    ));
                }
            };

            let new_serial = generate_serial(Some(zone.serial));
            let updated_zone = RepositoryService::update_zone_tx(
                &mut tx,
                Zone {
                    serial: new_serial,
                    ..zone.clone()
                },
            )
            .await
            .map_err(|e| {
                log_error!("Failed to force increment zone serial: {}", e);
                ServiceError::Internal("Failed to force increment zone serial".to_string())
            })?;

            save_zone_snapshot_tx(&mut tx, &updated_zone, new_serial).await?;

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
