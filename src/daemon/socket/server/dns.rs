use crate::{
    daemon::socket::dto::DaemonResponse, rndc::get_rndc_client, serializer::get_serializer,
};

pub fn write_dns_config() -> Result<DaemonResponse, String> {
    match get_serializer().send_message_and_wait("write_config") {
        Ok(_) => Ok(DaemonResponse {
            message: "DNS configuration written successfully.".to_string(),
            data: serde_json::Value::Null,
        }),
        Err(e) => Err(format!("Failed to write DNS configuration: {}", e)),
    }
}

pub fn reload_dns_config() -> Result<DaemonResponse, String> {
    match get_serializer().send_message_and_wait("reload") {
        Ok(_) => Ok(DaemonResponse {
            message: "DNS configuration reloaded successfully.".to_string(),
            data: serde_json::Value::Null,
        }),
        Err(e) => Err(format!("Failed to reload DNS configuration: {}", e)),
    }
}

pub fn get_dns_status() -> Result<DaemonResponse, String> {
    match get_rndc_client().command("status") {
        Ok(response) => {
            if !response.result {
                return Err("Failed to get DNS status".to_string());
            }
            Ok(DaemonResponse {
                message: "DNS status retrieved successfully.".to_string(),
                data: serde_json::json!({
                    "status": response.text.unwrap_or_else(|| "No status text available".to_string())
                }),
            })
        }
        Err(e) => Err(format!("Failed to get DNS status: {}", e)),
    }
}
