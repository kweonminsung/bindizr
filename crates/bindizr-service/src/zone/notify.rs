//! Manual NOTIFY orchestration; delivery goes through the registered sender.

use crate::{
    Context, authorization::Caller, error::ServiceError, notify::NotifyTarget, types::NotifySerial,
};

/// Send a manual NOTIFY for one zone or all zones, bumping the serial
/// first when `serial` says to.
pub async fn notify(
    cx: &Context,
    caller: &Caller,
    target: NotifyTarget<'_>,
    serial: NotifySerial,
) -> Result<(), ServiceError> {
    // Forcing bumps zone serials — a zone-plane mutation, not just a NOTIFY.
    if serial == NotifySerial::Bump {
        caller.authorize_global("force a NOTIFY")?;
    }
    match target {
        // The virtual catalog zone has no row: nothing to bump, and no
        // zone grant can cover it, so only a global caller may notify it.
        NotifyTarget::Zone(name) if cx.config().dns.is_catalog_zone(name.as_str()) => {
            caller.authorize_global("send NOTIFY for the catalog zone")?;
            if serial == NotifySerial::Bump {
                log::info!("Skipping forced serial increment for virtual catalog zone");
            }
        }
        // Resolving the zone for `caller` is also the visibility check.
        NotifyTarget::Zone(name) => {
            super::get_by_name(cx, caller, name).await?;
            if serial == NotifySerial::Bump {
                super::force_increment_serial(cx, target, &caller.change_subject()).await?;
            }
        }
        NotifyTarget::All => {
            caller.authorize_global("send NOTIFY for all zones")?;
            if serial == NotifySerial::Bump {
                super::force_increment_serial(cx, target, &caller.change_subject()).await?;
            }
        }
    }

    Ok(crate::notify::send_notify(cx, target).await?)
}
