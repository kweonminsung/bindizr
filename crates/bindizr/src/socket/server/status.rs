use std::process;

use crate::{
    config,
    socket::types::{DaemonResponse, DaemonStatusResponse},
};

pub(super) fn get_status() -> Result<DaemonResponse, String> {
    let pid = Some(process::id());
    let version = env!("CARGO_PKG_VERSION");
    let status = DaemonStatusResponse {
        pid,
        version: version.to_string(),
        config: config::get_bindizr_config().clone(),
    };

    let response = DaemonResponse {
        message: "Status retrieved successfully".to_string(),
        data: serde_json::to_value(status)
            .map_err(|e| format!("Failed to serialize status response: {}", e))?,
    };
    Ok(response)
}
