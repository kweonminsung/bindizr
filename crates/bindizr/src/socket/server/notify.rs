use bindizr_service::{
    authorization::Caller, error::ServiceError, types::build_notify_message, zone::ZoneService,
};

use crate::socket::{
    server::parse_params,
    types::{DaemonResponse, NotifyAllZonesParams, NotifyZoneParams},
};

/// Handle the `NotifyAllZones` command by sending DNS NOTIFY for every zone.
pub(crate) async fn notify_all_zones(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let params: NotifyAllZonesParams = parse_params(data)?;

    ZoneService::notify(&Caller::Global, None, params.bump_serial).await?;

    Ok(DaemonResponse {
        message: build_notify_message(None, params.bump_serial),
        data: serde_json::Value::Null,
    })
}

/// Handle the `NotifyZone` command by sending DNS NOTIFY for one zone.
pub(crate) async fn notify_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let params: NotifyZoneParams = parse_params(data)?;

    ZoneService::notify(&Caller::Global, Some(&params.zone_name), params.bump_serial).await?;

    Ok(DaemonResponse {
        message: build_notify_message(Some(&params.zone_name), params.bump_serial),
        data: serde_json::Value::Null,
    })
}
