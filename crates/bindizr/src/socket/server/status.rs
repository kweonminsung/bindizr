use std::{
    process,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use bindizr_core::config;
use bindizr_service::error::ServiceError;

use crate::socket::{
    server::to_response_data,
    types::{DaemonResponse, DaemonStatusResponse},
};

static STARTED_AT_MS: OnceLock<u64> = OnceLock::new();

/// Record the daemon start time; restart detection compares it across execs.
pub(super) fn record_start_time() {
    let _ = STARTED_AT_MS.set(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    );
}

/// Handle the `Status` command by returning the daemon's PID, version, and config.
pub(super) fn status() -> Result<DaemonResponse, ServiceError> {
    let pid = Some(process::id());
    let version = env!("CARGO_PKG_VERSION");
    let status = DaemonStatusResponse {
        pid,
        version: version.to_string(),
        started_at_ms: STARTED_AT_MS.get().copied().unwrap_or(0),
        config: config::bindizr_config().clone(),
    };

    let response = DaemonResponse {
        message: "Status retrieved successfully".to_string(),
        data: to_response_data(status)?,
    };
    Ok(response)
}
