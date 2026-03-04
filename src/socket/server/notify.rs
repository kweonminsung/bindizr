use crate::socket::dto::DaemonResponse;
use crate::xfr;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug)]
pub struct NotifyZoneRequest {
    pub zone_name: String,
}

pub async fn handle_notify_zone(data: serde_json::Value) -> Result<DaemonResponse, String> {
    let request: NotifyZoneRequest = match serde_json::from_value(data) {
        Ok(req) => req,
        Err(e) => {
            return Ok(DaemonResponse {
                message: format!("Invalid request: {}", e),
                data: json!(null),
            });
        }
    };

    match xfr::notify::send_notify(&request.zone_name).await {
        Ok(()) => Ok(DaemonResponse {
            message: format!("NOTIFY sent successfully for zone: {}", request.zone_name),
            data: json!(null),
        }),
        Err(e) => Ok(DaemonResponse {
            message: format!("Failed to send NOTIFY: {}", e),
            data: json!(null),
        }),
    }
}
