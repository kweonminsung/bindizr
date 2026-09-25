use std::{net::SocketAddr, time::Duration};

use bindizr_core::{config, dns::address::loopback_if_unspecified};
use bindizr_service::{
    authorization::Caller,
    dns_client::{notify, probe},
    error::ServiceError,
    zone::ZoneService,
};

use crate::socket::{
    server::to_response_data,
    types::{DaemonDoctorResponse, DaemonResponse, DoctorCheckResult},
};

/// A hung database must become a failed check, not a hung doctor.
const DB_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// The daemon-side installation checks. The catalog zone is the one probed
/// because it exists before any user zone, so serial comparison always works.
pub(crate) async fn check_installation() -> Result<DaemonResponse, ServiceError> {
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

    // Probe the local catalog SOA to supply the reference serial for diagnosis.
    let dns_addr = SocketAddr::new(
        loopback_if_unspecified(config.dns.listen_addr),
        config.dns.listen_port,
    );
    let timeout = Duration::from_secs(config.dns.notify.timeout_secs);

    let (dns_server, catalog_serial) =
        match probe::probe_server(dns_addr, &config.dns.catalog_zone_name, timeout).await {
            Ok(serial) => (
                DoctorCheckResult {
                    ok: true,
                    detail: format!(
                        "{} (catalog zone {} at serial {})",
                        dns_addr, config.dns.catalog_zone_name, serial
                    ),
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

    // Capture secondary serials before the NOTIFY check can trigger a refresh.
    let secondaries = probe::probe_secondaries(&config.dns.catalog_zone_name, catalog_serial)
        .await
        .map_err(ServiceError::internal)?;

    // Actively test NOTIFY delivery; this can prompt secondaries to transfer the catalog.
    let notifies = notify::send_notify_to_secondaries(&config.dns.catalog_zone_name)
        .await
        .map_err(ServiceError::internal)?;

    let response = DaemonDoctorResponse {
        database,
        dns_server,
        catalog_zone_name: config.dns.catalog_zone_name.clone(),
        catalog_serial,
        secondaries,
        notifies,
    };

    Ok(DaemonResponse {
        message: "Doctor checks completed".to_string(),
        data: to_response_data(response)?,
    })
}
