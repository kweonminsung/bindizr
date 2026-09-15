use std::{
    process,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use bindizr_core::{config, log_info};
use bindizr_service::error::ServiceError;

use crate::socket::{
    server::to_response_data,
    types::{DaemonResponse, DaemonStatusResponse},
};

static STARTED_AT_MS: OnceLock<u64> = OnceLock::new();

/// Mark the daemon start time; restart detection compares it across execs.
pub(crate) fn mark_start_time() {
    let _ = STARTED_AT_MS.set(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    );
}

/// Return the daemon's current status as JSON.
pub(crate) fn status() -> Result<DaemonResponse, ServiceError> {
    let pid = Some(process::id());
    let version = env!("CARGO_PKG_VERSION");
    let status = DaemonStatusResponse {
        pid,
        version: version.to_string(),
        started_at_ms: STARTED_AT_MS.get().copied().unwrap_or(0),
    };

    let response = DaemonResponse {
        message: "Status retrieved successfully".to_string(),
        data: to_response_data(status)?,
    };
    Ok(response)
}

/// Reload the daemon configuration and return the result.
pub(crate) fn reload_config() -> Result<DaemonResponse, ServiceError> {
    let changed = crate::daemon::reload_config().map_err(ServiceError::invalid_input)?;

    let message = if changed.is_empty() {
        "Configuration reloaded; nothing changed".to_string()
    } else {
        format!("Configuration reloaded: {} changed", changed.join(", "))
    };
    log_info!("event=config_reload changed={}", changed.join(","));
    Ok(DaemonResponse {
        message,
        data: serde_json::Value::Null,
    })
}

/// Return the daemon's effective configuration as JSON.
pub(crate) fn config() -> Result<DaemonResponse, ServiceError> {
    Ok(DaemonResponse {
        message: "Configuration retrieved successfully".to_string(),
        data: to_response_data(config::bindizr_config())?,
    })
}
