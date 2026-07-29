use std::{net::SocketAddr, time::Duration};

use bindizr_core::{config, dns::CATALOG_ZONE_NAME};
use bindizr_dns::client::{notify, probe};
use bindizr_service::{error::ServiceError, zone::ZoneService};

use crate::{
    net::loopback_if_unspecified,
    socket::{
        server::to_response_data,
        types::{DaemonDoctorResponse, DaemonResponse, DoctorCheckResult, DoctorProbeResult},
    },
};

/// Handle the `Doctor` command: the daemon-side installation checks. The
/// catalog zone is probed because it exists on every installation, so serial
/// comparison works before any user zone is created.
pub(super) async fn doctor() -> Result<DaemonResponse, ServiceError> {
    let config = config::get_bindizr_config();

    let database = match ZoneService::list().await {
        Ok(zones) => DoctorCheckResult {
            ok: true,
            detail: format!("{} ({} zones)", config.database.database_type, zones.len()),
        },
        Err(e) => DoctorCheckResult {
            ok: false,
            detail: e.to_string(),
        },
    };

    let dns_addr = SocketAddr::new(
        loopback_if_unspecified(config.dns.listen_addr),
        config.dns.listen_port,
    );
    let timeout = Duration::from_secs(config.dns.notify_timeout_secs);

    let (dns_server, catalog_serial) =
        match probe::probe_server(dns_addr, CATALOG_ZONE_NAME, timeout).await {
            Ok(serial) => (
                DoctorCheckResult {
                    ok: true,
                    detail: format!("{} (catalog serial {})", dns_addr, serial),
                },
                Some(serial),
            ),
            Err(e) => (
                DoctorCheckResult {
                    ok: false,
                    detail: format!("{}: {}", dns_addr, e),
                },
                None,
            ),
        };

    let secondaries = probe::probe_secondaries(CATALOG_ZONE_NAME)
        .await
        .map_err(|e| ServiceError::internal(e.to_string()))?
        .into_iter()
        .map(|probe| match probe.result {
            Ok(serial) => DoctorProbeResult {
                address: probe.address,
                serial: Some(serial),
                error: None,
            },
            Err(error) => DoctorProbeResult {
                address: probe.address,
                serial: None,
                error: Some(error),
            },
        })
        .collect();

    let notifies = notify::notify_secondaries(CATALOG_ZONE_NAME)
        .await
        .map_err(|e| ServiceError::internal(e.to_string()))?
        .into_iter()
        .map(|notify| DoctorProbeResult {
            address: notify.address,
            serial: None,
            error: notify.result.err(),
        })
        .collect();

    let response = DaemonDoctorResponse {
        database,
        dns_server,
        catalog_serial,
        secondaries,
        notifies,
    };

    Ok(DaemonResponse {
        message: "Doctor checks completed".to_string(),
        data: to_response_data(response)?,
    })
}
