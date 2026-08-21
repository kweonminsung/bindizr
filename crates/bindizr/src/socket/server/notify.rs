use bindizr_service::{
    authorization::Caller, error::ServiceError, types::NotifyZoneRequest, zone::ZoneService,
};
use serde_json::json;

use crate::socket::{server::parse_params, types::DaemonResponse};

/// Handle the `NotifyZone` command by sending DNS NOTIFY for a zone or all zones.
pub(super) async fn handle_notify_zone(
    data: &serde_json::Value,
) -> Result<DaemonResponse, ServiceError> {
    let request: NotifyZoneRequest = parse_params(data)?;

    // The daemon socket is root-local, so commands run as the global caller.
    ZoneService::notify(
        &Caller::Global,
        request.zone_name.as_deref(),
        request.bump_serial,
    )
    .await?;

    Ok(DaemonResponse {
        message: match request.zone_name {
            Some(ref name) if request.bump_serial => {
                format!(
                    "NOTIFY sent successfully for zone: {} (serial bumped)",
                    name
                )
            }
            Some(ref name) => format!("NOTIFY sent successfully for zone: {}", name),
            None if request.bump_serial => {
                "NOTIFY sent successfully for all zones (serial bumped)".to_string()
            }
            None => "NOTIFY sent successfully for all zones".to_string(),
        },
        data: json!(null),
    })
}
