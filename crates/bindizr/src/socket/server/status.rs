use std::{
    net::SocketAddr,
    process,
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bindizr_core::config;
use bindizr_service::{error::ServiceError, types::MessageResponse, zone::ZoneService};

use crate::socket::{
    server::to_response_data,
    types::{DaemonResponse, DaemonStatusResponse},
};

static STARTED_AT_MS: OnceLock<u64> = OnceLock::new();

/// A silent database must not keep status from answering.
const DB_COUNT_TIMEOUT: Duration = Duration::from_secs(3);

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
pub(crate) async fn handle_status() -> Result<DaemonResponse, ServiceError> {
    let config = config::bindizr_config();
    let (zones, database_error) =
        match tokio::time::timeout(DB_COUNT_TIMEOUT, ZoneService::count_all()).await {
            Ok(Ok(zones)) => (Some(zones), None),
            Ok(Err(e)) => (None, Some(e.to_string())),
            Err(_) => (
                None,
                Some(format!(
                    "timed out after {} seconds",
                    DB_COUNT_TIMEOUT.as_secs()
                )),
            ),
        };
    let scheme = if config.api.tls_files().is_some() {
        "https"
    } else {
        "http"
    };
    let status = DaemonStatusResponse {
        pid: Some(process::id()),
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at_ms: STARTED_AT_MS.get().copied().unwrap_or(0),
        api_url: format!(
            "{}://{}",
            scheme,
            SocketAddr::new(config.api.listen_addr, config.api.listen_port)
        ),
        api_authentication: config.api.authentication_required,
        dns_addr: SocketAddr::new(config.dns.listen_addr, config.dns.listen_port).to_string(),
        database_type: config.database.database_type.to_string(),
        secondaries: config
            .dns
            .secondary_addrs
            .split(',')
            .filter(|entry| !entry.trim().is_empty())
            .count(),
        zones,
        database_error,
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
    log::info!("event=config_reload changed={}", changed.join(","));
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Return the daemon's effective configuration as JSON.
pub(crate) fn config() -> Result<DaemonResponse, ServiceError> {
    Ok(DaemonResponse {
        message: "Configuration retrieved successfully".to_string(),
        data: to_response_data(config::bindizr_config())?,
    })
}
