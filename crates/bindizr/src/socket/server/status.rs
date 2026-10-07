use std::{net::SocketAddr, process, sync::Arc};

use bindizr_core::config::Config;
use bindizr_service::{Context, error::ServiceError, secondary, types::MessageResponse, zone};

use crate::{
    daemon::db_probe::DB_PROBE_TIMEOUT,
    socket::types::{DaemonResponse, DaemonStatusResponse},
};

/// Return the daemon's current status as JSON.
pub(crate) async fn handle_status(
    cx: &Context,
) -> Result<DaemonResponse<DaemonStatusResponse>, ServiceError> {
    let config = cx.config();
    let counts = async {
        let zones = zone::count_all(cx).await?;
        let secondaries = secondary::list_enabled(cx).await?.len();
        Ok::<_, ServiceError>((zones, secondaries))
    };
    let (zones, secondaries, database_error) =
        match tokio::time::timeout(DB_PROBE_TIMEOUT, counts).await {
            Ok(Ok((zones, secondaries))) => (Some(zones), Some(secondaries), None),
            Ok(Err(e)) => (None, None, Some(e.to_string())),
            Err(_) => (
                None,
                None,
                Some(format!(
                    "timed out after {} seconds",
                    DB_PROBE_TIMEOUT.as_secs()
                )),
            ),
        };
    let scheme = if config.api.tls.tls_files().is_some() {
        "https"
    } else {
        "http"
    };
    let status = DaemonStatusResponse {
        pid: Some(process::id()),
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at_ms: cx.started_at().map_or(0, |at| at.timestamp_millis() as u64),
        api_url: format!(
            "{}://{}",
            scheme,
            SocketAddr::new(config.api.listen_addr, config.api.listen_port)
        ),
        api_authentication: config.api.authentication_required,
        dns_addr: SocketAddr::new(config.dns.listen_addr, config.dns.listen_port).to_string(),
        dns_tls_addr: config.dns.tls.tls_files().map(|_| {
            SocketAddr::new(config.dns.listen_addr, config.dns.tls.listen_port).to_string()
        }),
        database_type: config.database.database_type.to_string(),
        secondaries,
        zones,
        database_error,
    };

    Ok(DaemonResponse {
        message: "Status retrieved successfully".to_string(),
        data: status,
    })
}

/// Reload the daemon configuration and return the result.
pub(crate) fn reload_config(cx: &Context) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let changed = crate::daemon::reload_config(cx)?;

    let message = if changed.is_empty() {
        "Configuration reloaded; nothing changed".to_string()
    } else {
        format!("Configuration reloaded: {} changed", changed.join(", "))
    };
    log::info!("event=config_reload changed={}", changed.join(","));
    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Return the daemon's effective configuration.
pub(crate) fn config(cx: &Context) -> DaemonResponse<Arc<Config>> {
    DaemonResponse {
        message: "Configuration retrieved successfully".to_string(),
        data: cx.config(),
    }
}
