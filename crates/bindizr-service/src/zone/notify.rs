//! Manual NOTIFY requests after authorization and optional zone serial increments.

use std::sync::Arc;

use bindizr_core::model::role_grant::Action;

use crate::{
    Context, authorization::Caller, error::ServiceError, notify::NotifyTarget, types::NotifySerial,
};

/// Send a manual NOTIFY for one zone or all zones, bumping the serial
/// first when `serial` says to; an all-zones round runs the zones concurrently.
pub async fn notify(
    cx: &Arc<Context>,
    caller: &Caller,
    target: NotifyTarget<'_>,
    serial: NotifySerial,
) -> Result<(), ServiceError> {
    match target {
        // The virtual catalog zone has no row to bump and lists all zones.
        NotifyTarget::Zone(name) if name == &cx.config().dns.catalog_zone_name => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                log::info!("Skipping forced serial increment for virtual catalog zone");
            }
        }
        NotifyTarget::Zone(name) => {
            let zone = super::lookup_by_name(cx, name).await?;
            caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
            if serial == NotifySerial::Bump {
                super::force_increment_serial(cx, caller, name).await?;
            }
        }
        NotifyTarget::All => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                for zone in super::list(cx).await? {
                    super::force_increment_serial(cx, caller, &zone.name).await?;
                }
            }
        }
    }

    Ok(crate::notify::send_notify(cx, target).await?)
}
