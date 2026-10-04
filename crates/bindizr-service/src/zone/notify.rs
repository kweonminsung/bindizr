//! Manual NOTIFY orchestration; delivery goes through the registered sender.

use bindizr_core::model::role_grant::Action;

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
    match target {
        // The virtual catalog zone has no row to bump and lists all zones.
        NotifyTarget::Zone(name) if cx.config().dns.is_catalog_zone(name.as_str()) => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                log::info!("Skipping forced serial increment for virtual catalog zone");
            }
        }
        NotifyTarget::Zone(name) => {
            let zone = super::lookup_by_name(cx, name).await?;
            caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
            if serial == NotifySerial::Bump {
                super::force_increment_serial(cx, caller, target).await?;
            }
        }
        NotifyTarget::All => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                super::force_increment_serial(cx, caller, target).await?;
            }
        }
    }

    Ok(crate::notify::send_notify(cx, target).await?)
}
