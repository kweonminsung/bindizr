//! Manual NOTIFY orchestration; delivery goes through the registered sender.

use crate::{Context, authorization::Caller, error::ServiceError};

/// Send a manual NOTIFY for one zone or all zones, optionally forcing a
/// serial bump first.
pub async fn notify(
    cx: &Context,
    caller: &Caller,
    zone_name: Option<&str>,
    force: bool,
) -> Result<(), ServiceError> {
    // Forcing bumps zone serials — a zone-plane mutation, not just a NOTIFY.
    if force {
        caller.authorize_global("force a NOTIFY")?;
    }
    match zone_name {
        // The virtual catalog zone has no row: nothing to bump, and no
        // zone grant can cover it, so only a global caller may notify it.
        Some(name) if cx.config().dns.is_catalog_zone(name) => {
            caller.authorize_global("send NOTIFY for the catalog zone")?;
            if force {
                log::info!("Skipping forced serial increment for virtual catalog zone");
            }
        }
        // Resolving the zone for `caller` is also the visibility check.
        Some(name) => {
            super::get_by_name(cx, caller, name).await?;
            if force {
                super::force_increment_serial(cx, zone_name, &caller.change_subject()).await?;
            }
        }
        None => {
            caller.authorize_global("send NOTIFY for all zones")?;
            if force {
                super::force_increment_serial(cx, zone_name, &caller.change_subject()).await?;
            }
        }
    }

    crate::notify::send_notify(cx, zone_name)
        .await
        .map_err(ServiceError::internal)
}
