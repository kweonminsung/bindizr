//! Manual NOTIFY requests after authorization and optional zone serial increments.

use std::sync::Arc;

use bindizr_core::model::role_grant::Action;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::notify::NotifyTarget;
use crate::types::{MessageResponse, NotifySerial};
use crate::{Context, notify, zone};

/// Send a manual NOTIFY for one zone or all zones, bumping the serial
/// first when `serial` says to; an all-zones round runs the zones concurrently.
pub async fn notify(
    cx: &Arc<Context>,
    caller: &Caller,
    target: NotifyTarget<'_>,
    serial: NotifySerial,
) -> Result<MessageResponse, ServiceError> {
    let mut serial_bumped = false;
    match target {
        // The virtual catalog zone has no row to bump and lists all zones.
        NotifyTarget::Zone(zone_name) if zone_name == &cx.config().dns.catalog_zone_name => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                log::info!("Skipping forced serial increment for virtual catalog zone");
            }
        }
        NotifyTarget::Zone(zone_name) => {
            let zone = zone::lookup_by_name(cx, zone_name).await?;
            caller.authorize_zone_action(Action::ZoneUpdate, &zone)?;
            if !zone.enabled {
                return Err(ServiceError::invalid_input(format!(
                    "zone '{zone_name}' is disabled, so the DNS plane does not serve it; enable it to send NOTIFY"
                )));
            }
            if serial == NotifySerial::Bump {
                zone::force_increment_serial(cx, caller, zone_name).await?;
                serial_bumped = true;
            }
        }
        NotifyTarget::All => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                for zone in zone::list(cx).await? {
                    zone::force_increment_serial(cx, caller, &zone.name).await?;
                    serial_bumped = true;
                }
            }
        }
    }

    notify::send_notify(cx, target).await?;

    let scope = match target {
        NotifyTarget::Zone(zone_name) => format!("zone: {zone_name}"),
        NotifyTarget::All => "all zones".to_string(),
    };
    let suffix = if serial_bumped {
        " (serial bumped)"
    } else {
        ""
    };

    Ok(MessageResponse {
        message: format!("NOTIFY sent successfully for {scope}{suffix}"),
    })
}

#[cfg(test)]
mod tests;
