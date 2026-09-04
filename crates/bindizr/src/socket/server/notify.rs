use bindizr_service::{
    authorization::Caller, error::ServiceError, types::NotifyZoneRequest, zone::ZoneService,
};
use serde_json::json;

use crate::socket::{server::parse_params, types::DaemonResponse};

/// Handle the `NotifyZone` command by sending DNS NOTIFY for a zone or all zones.
pub(crate) async fn notify_zone(data: &serde_json::Value) -> Result<DaemonResponse, ServiceError> {
    let request: NotifyZoneRequest = parse_params(data)?;

    ZoneService::notify(
        &Caller::Global,
        request.zone_name.as_deref(),
        request.bump_serial,
    )
    .await?;

    Ok(DaemonResponse {
        message: request.success_message(),
        data: json!(null),
    })
}
