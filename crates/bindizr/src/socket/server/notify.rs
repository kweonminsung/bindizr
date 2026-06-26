use bindizr_dns as dns;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::socket::types::DaemonResponse;

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct NotifyZoneRequest {
    pub zone_name: Option<String>,
    #[serde(default)]
    pub force: bool,
}

pub(super) async fn handle_notify_zone(data: serde_json::Value) -> Result<DaemonResponse, String> {
    let request: NotifyZoneRequest = match serde_json::from_value(data) {
        Ok(req) => req,
        Err(e) => {
            return Ok(DaemonResponse {
                message: format!("Invalid request: {}", e),
                data: json!(null),
            });
        }
    };

    match dns::xfr::notify::send_notify(request.zone_name.as_deref(), request.force).await {
        Ok(()) => Ok(DaemonResponse {
            message: match request.zone_name {
                Some(ref name) if request.force => {
                    format!("NOTIFY sent successfully for zone: {} (forced)", name)
                }
                Some(ref name) => format!("NOTIFY sent successfully for zone: {}", name),
                None if request.force => {
                    "NOTIFY sent successfully for all zones (forced)".to_string()
                }
                None => "NOTIFY sent successfully for all zones".to_string(),
            },
            data: json!(null),
        }),
        Err(e) => Ok(DaemonResponse {
            message: format!("Failed to send NOTIFY: {}", e),
            data: json!(null),
        }),
    }
}
