use crate::{config, socket::dto::DaemonResponse};
use std::process;

pub fn get_status() -> Result<DaemonResponse, String> {
    let pid = Some(process::id());
    let version = env!("CARGO_PKG_VERSION");
    let config_map_json = config::get_config_json_map()
        .map_err(|e| format!("Failed to collect configuration: {}", e))?;

    let response = DaemonResponse {
        message: "Status retrieved successfully".to_string(),
        data: serde_json::json!({
            "pid": pid,
            "version": version,
            "config_map": config_map_json,
        }),
    };
    Ok(response)
}
