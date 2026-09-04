use std::{net::SocketAddr, time::Duration};

use bindizr_core::{config, dns::CATALOG_ZONE_NAME};
use bindizr_service::{
    authorization::Caller,
    dns_client::{notify, probe},
    error::ServiceError,
    zone::ZoneService,
};

use crate::{
    net::loopback_if_unspecified,
    socket::{
        server::to_response_data,
        types::{DaemonDoctorResponse, DaemonResponse, DoctorCheckResult, DoctorProbeResult},
    },
};

/// A hung database must become a failed check, not a hung doctor.
const DB_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// The daemon-side installation checks. The catalog zone is the one probed
/// because it exists before any user zone, so serial comparison always works.
pub(crate) async fn doctor() -> Result<DaemonResponse, ServiceError> {
    let config = config::bindizr_config();

    // Count zones without materializing them; large tables must fit the deadline.
    let zones_probe = ZoneService::count(&Caller::Global);
    let database = match tokio::time::timeout(DB_CHECK_TIMEOUT, zones_probe).await {
        Ok(Ok(total)) => DoctorCheckResult {
            ok: true,
            detail: format!("{} ({} zones)", config.database.database_type, total),
        },
        Ok(Err(e)) => DoctorCheckResult {
            ok: false,
            detail: e.to_string(),
        },
        Err(_) => DoctorCheckResult {
            ok: false,
            detail: format!(
                "database check timed out after {} seconds",
                DB_CHECK_TIMEOUT.as_secs()
            ),
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
        .map_err(ServiceError::internal)?
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
        .map_err(ServiceError::internal)?
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
