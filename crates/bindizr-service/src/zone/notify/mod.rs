//! Manual NOTIFY requests after authorization and optional zone serial increments.

mod serial;

use std::sync::Arc;

use bindizr_core::dns::name::ZoneName;
use bindizr_core::model::activity_log::{ActivityOperation, ActivityResult};
use bindizr_core::model::role_grant::Action;
use serial::bump_zone_serial;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::notify::NotifyTarget;
use crate::types::{MessageResponse, NotifySerial};
use crate::{Context, notify, zone};

/// Send a manual NOTIFY for one zone or all enabled zones, bumping the serial
/// first when `serial` says to; an all-zones round runs the zones concurrently.
/// If a bump fails partway through an all-zones round, announce the committed ones.
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
            let disabled_zone = || {
                ServiceError::invalid_input(format!(
                    "zone '{zone_name}' is disabled, so the DNS plane does not serve it; enable it to send NOTIFY"
                ))
            };
            if !zone.enabled {
                return Err(disabled_zone());
            }
            if serial == NotifySerial::Bump {
                serial_bumped = bump_zone_serial(cx, caller, zone_name).await?;
                if !serial_bumped {
                    return Err(disabled_zone());
                }
            }
        }
        NotifyTarget::All => {
            caller.authorize_action(Action::ZoneUpdate)?;
            if serial == NotifySerial::Bump {
                let zones = zone::list_enabled(cx).await?;
                serial_bumped =
                    bump_zone_serials(cx, caller, zones.into_iter().map(|zone| zone.name)).await?;
            }
        }
    }

    notify::send_notify(cx, target).await?;

    if !serial_bumped {
        let activity_target = match target {
            NotifyTarget::Zone(zone_name) => zone::activity_target(zone_name),
            NotifyTarget::All => Default::default(),
        };
        crate::activity::save_result(
            cx,
            ActivityOperation::ZoneNotify,
            ActivityResult::Succeeded,
            activity_target,
            caller.change_origin(),
        )
        .await;
    }

    let scope = match target {
        NotifyTarget::Zone(zone_name) => format!("zone: {zone_name}"),
        NotifyTarget::All => "all enabled zones".to_string(),
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

/// Bump the selected zones in order. If a later bump fails, announce the
/// committed changes before returning that failure.
async fn bump_zone_serials(
    cx: &Arc<Context>,
    caller: &Caller,
    zone_names: impl IntoIterator<Item = ZoneName>,
) -> Result<bool, ServiceError> {
    let mut bumped = Vec::new();
    for zone_name in zone_names {
        match bump_zone_serial(cx, caller, &zone_name).await {
            Ok(true) => bumped.push(zone_name),
            Ok(false) => {}
            Err(error) => {
                if let Err(notify_error) = notify::send_zone_notifies(cx, bumped).await {
                    log::warn!(
                        "Failed to send NOTIFY for committed zones after a serial bump failed: {notify_error:?}"
                    );
                }
                return Err(error);
            }
        }
    }

    Ok(!bumped.is_empty())
}

#[cfg(test)]
mod tests;
