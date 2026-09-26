use std::{net::SocketAddr, time::Duration};

use bindizr_core::{config, dns::address::loopback_if_unspecified};
use bindizr_service::{
    authorization::Caller,
    dns_client::{notify, probe},
    error::ServiceError,
    zone::ZoneService,
};

use crate::{
    daemon::DB_PROBE_TIMEOUT,
    socket::{
        server::to_response_data,
        types::{DaemonDoctorResponse, DaemonResponse, DoctorCheck, DoctorCheckStatus},
    },
};

/// The daemon-side installation checks. The catalog zone is the one probed
/// because it exists before any user zone, so serial comparison always works.
pub(crate) async fn check_installation() -> Result<DaemonResponse, ServiceError> {
    let config = config::bindizr_config();

    // Count zones without materializing them; large tables must fit the deadline.
    let zones_probe = ZoneService::count(&Caller::Global);
    let database = match tokio::time::timeout(DB_PROBE_TIMEOUT, zones_probe).await {
        Ok(Ok(total)) => DoctorCheck {
            status: DoctorCheckStatus::Ok,
            message: format!(
                "Database connected: {} ({} zones)",
                config.database.database_type, total
            ),
        },
        Ok(Err(e)) => DoctorCheck {
            status: DoctorCheckStatus::Fail,
            message: format!("Database not reachable: {}", e),
        },
        Err(_) => DoctorCheck {
            status: DoctorCheckStatus::Fail,
            message: format!(
                "Database not reachable: timed out after {} seconds",
                DB_PROBE_TIMEOUT.as_secs()
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
                DoctorCheck {
                    status: DoctorCheckStatus::Ok,
                    message: format!(
                        "DNS server reachable: {} (catalog zone {} at serial {})",
                        dns_addr, config.dns.catalog_zone_name, serial
                    ),
                },
                Some(serial),
            ),
            Err(e) => (
                DoctorCheck {
                    status: DoctorCheckStatus::Fail,
                    message: format!("DNS server not reachable: {}: {}", dns_addr, e),
                },
                None,
            ),
        };

    // The secondaries are rows: a database that did not answer is not asked
    // for them again.
    let (secondaries, notifies) = if database.status == DoctorCheckStatus::Fail {
        (Vec::new(), Vec::new())
    } else {
        // Capture secondary serials before the NOTIFY check can trigger a refresh.
        let secondaries = probe::probe_secondaries(&config.dns.catalog_zone_name, catalog_serial)
            .await
            .map_err(ServiceError::internal)?;
        // Actively test NOTIFY delivery; this can prompt secondaries to transfer the catalog.
        let notifies = notify::send_notify_to_secondaries(&config.dns.catalog_zone_name)
            .await
            .map_err(ServiceError::internal)?;
        (secondaries, notifies)
    };

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
