use std::sync::Arc;

use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    notify::NotifyTarget,
    types::{MessageResponse, NotifySerial, build_notify_message},
    zone,
};

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
    zone::notify(cx, &Caller::socket(), target, serial).await?;
    let message = build_notify_message(target, serial);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
