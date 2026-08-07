//! Manual NOTIFY orchestration; delivery goes through the registered sender.

use bindizr_core::dns::is_catalog_zone;

use super::ZoneService;
use crate::{authorization::Caller, error::ServiceError, log_info};

impl ZoneService {
    /// Send a manual NOTIFY for one zone or all zones, optionally forcing a
    /// serial bump first.
    pub async fn notify_for(
        caller: &Caller,
        zone_name: Option<&str>,
        force: bool,
    ) -> Result<(), ServiceError> {
        // Forcing bumps zone serials — a zone-plane mutation, not just a NOTIFY.
        if force {
            caller.require_global("force a NOTIFY")?;
        }
        match zone_name {
            Some(zone_name) => Self::ensure_visible(caller, zone_name).await?,
            None => caller.require_global("send NOTIFY for all zones")?,
        }

        match zone_name {
            // The virtual catalog zone has no row: nothing to bump or look up.
            Some(name) if is_catalog_zone(name) => {
                if force {
                    log_info!("Skipping forced serial increment for virtual catalog zone");
                }
            }
            _ if force => {
                Self::force_increment_serial(zone_name).await?;
            }
            Some(name) => {
                Self::get_by_name(name).await?;
            }
            None => {}
        }

        crate::notify::send_notify(zone_name)
            .await
            .map_err(ServiceError::internal)
    }
}
