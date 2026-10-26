use std::sync::Arc;

use bindizr_service::authorization::Caller;
use bindizr_service::error::ServiceError;
use bindizr_service::notify::NotifyTarget;
use bindizr_service::types::{MessageResponse, NotifySerial};
use bindizr_service::{Context, zone};

use crate::socket::types::DaemonResponse;

/// Send NOTIFY requests for one zone.
pub(crate) async fn notify_zone(
    cx: &Arc<Context>,
    zone_name: &str,
    serial: NotifySerial,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let zone_name = zone::normalize_name(zone_name)?;
    notify(cx, NotifyTarget::Zone(&zone_name), serial).await
}

/// Send NOTIFY requests for all zones.
pub(crate) async fn notify_all_zones(
    cx: &Arc<Context>,
    serial: NotifySerial,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    notify(cx, NotifyTarget::All, serial).await
}

/// Send NOTIFY requests for the zones `target` names.
async fn notify(
    cx: &Arc<Context>,
    target: NotifyTarget<'_>,
    serial: NotifySerial,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let response = zone::notify(cx, &Caller::socket(), target, serial).await?;
    Ok(DaemonResponse {
        message: response.message.clone(),
        data: response,
    })
}
