use bindizr_service::{
    authorization::Caller,
    error::ServiceError,
    types::{MessageResponse, build_notify_message},
    zone::ZoneService,
};

use crate::socket::{
    server::{parse_params, to_response_data},
    types::{DaemonResponse, NotifyAllZonesParams, NotifyZoneParams},
};

/// Request NOTIFY delivery for all eligible zones.
pub(crate) async fn notify_all_zones(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NotifyAllZonesParams = parse_params(data)?;

    ZoneService::notify(&Caller::Global, None, params.bump_serial).await?;

    let message = build_notify_message(None, params.bump_serial);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Request NOTIFY delivery for one zone.
pub(crate) async fn notify_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: NotifyZoneParams = parse_params(data)?;

    ZoneService::notify(&Caller::Global, Some(&params.zone_name), params.bump_serial).await?;

    let message = build_notify_message(Some(&params.zone_name), params.bump_serial);
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}
