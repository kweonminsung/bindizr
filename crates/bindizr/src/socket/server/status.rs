use std::process;

use bindizr_core::config;
use bindizr_service::error::ServiceError;

use crate::socket::{
    server::to_response_data,
    types::{DaemonResponse, DaemonStatusResponse},
};

/// Handle the `Status` command by returning the daemon's PID, version, and config.
pub(super) fn get_status() -> Result<DaemonResponse, ServiceError> {
    let pid = Some(process::id());
    let version = env!("CARGO_PKG_VERSION");
    let status = DaemonStatusResponse {
        pid,
        version: version.to_string(),
        config: config::get_bindizr_config().clone(),
    };

    let response = DaemonResponse {
        message: "Status retrieved successfully".to_string(),
        data: to_response_data(status)?,
    };
    Ok(response)
}
