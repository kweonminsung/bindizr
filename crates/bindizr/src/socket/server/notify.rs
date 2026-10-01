use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    notify::NotifyTarget,
    types::{MessageResponse, NotifySerial, build_notify_message},
    zone,
};

use crate::socket::types::DaemonResponse;

/// Request NOTIFY delivery for one zone.
pub(crate) async fn notify_zone(
    cx: &Context,
    zone_name: &str,
    serial: NotifySerial,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let zone_name = zone::normalize_name(zone_name)?;
    notify(cx, NotifyTarget::Zone(&zone_name), serial).await
}

/// Request NOTIFY delivery for every zone.
pub(crate) async fn notify_all_zones(
    cx: &Context,
    serial: NotifySerial,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    notify(cx, NotifyTarget::All, serial).await
}

/// Request NOTIFY delivery for the zones `target` names.
async fn notify(
    cx: &Context,
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
