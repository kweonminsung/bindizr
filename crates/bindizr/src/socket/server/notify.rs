use bindizr_service::{
    Context,
    authorization::Caller,
    error::ServiceError,
    notify::NotifyTarget,
    types::{MessageResponse, NotifySerial, build_notify_message},
    zone,
};

use crate::socket::types::DaemonResponse;

/// Request NOTIFY delivery for one zone, or for every zone.
pub(crate) async fn notify(
    cx: &Context,
    target: NotifyTarget<'_>,
    serial: NotifySerial,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    zone::notify(cx, &Caller::Global, target, serial).await?;
    let message = build_notify_message(target, serial);
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}
