use std::net::SocketAddr;

use bindizr_core::dns::address::loopback_if_unspecified;
use bindizr_service::{
    Context,
    authorization::Caller,
    dns_client::{notify, probe},
    error::ServiceError,
    secondary,
    types::SecondaryTransferSummary,
    zone,
};
use tokio::net::TcpStream;

use crate::{
    daemon::db_probe::DB_PROBE_TIMEOUT,
    socket::types::{DaemonDoctorResponse, DaemonResponse, DoctorCheck, DoctorCheckStatus},
};

/// The daemon-side installation checks. The catalog zone is the one probed
/// because it exists before any user zone, so serial comparison always works.
pub(crate) async fn check_installation(
    cx: &Context,
) -> Result<DaemonResponse<DaemonDoctorResponse>, ServiceError> {
    let config = cx.config();

    // Count zones without materializing them; large tables must fit the deadline.
    let caller = Caller::socket();
    let zones_probe = zone::count(cx, &caller);
    let database = match tokio::time::timeout(DB_PROBE_TIMEOUT, zones_probe).await {
        Ok(Ok(total)) => DoctorCheck {
            status: DoctorCheckStatus::Ok,
            message: format!(
                "Database connected: {} ({} zones)",
                config.database.database_type, total
            ),
        },
        Ok(Err(e)) => DoctorCheck {
            status: DoctorCheckStatus::Failed,
            message: format!("Database not reachable: {}", e),
        },
        Err(_) => DoctorCheck {
            status: DoctorCheckStatus::Failed,
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
    let timeout = config.dns.notify.timeout();

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
                    status: DoctorCheckStatus::Failed,
                    message: format!("DNS server not reachable: {}: {}", dns_addr, e),
                },
                None,
            ),
        };

    // A connection without a handshake, as the API's TLS check: trusting
    // whatever it presents would prove nothing.
    let dns_tls_server = match config.dns.tls.tls_files() {
        Some(_) => {
            let dns_tls_addr = SocketAddr::new(
                loopback_if_unspecified(config.dns.listen_addr),
                config.dns.tls.listen_port,
            );
            Some(
                match tokio::time::timeout(timeout, TcpStream::connect(dns_tls_addr)).await {
                    Ok(Ok(_)) => DoctorCheck {
                        status: DoctorCheckStatus::Ok,
                        message: format!(
                            "DNS TLS server listening: {} (TLS handshake not attempted)",
                            dns_tls_addr
                        ),
                    },
                    Ok(Err(e)) => DoctorCheck {
                        status: DoctorCheckStatus::Failed,
                        message: format!("DNS TLS server not reachable: {}: {}", dns_tls_addr, e),
                    },
                    Err(_) => DoctorCheck {
                        status: DoctorCheckStatus::Failed,
                        message: format!(
                            "DNS TLS server not reachable: {}: timed out",
                            dns_tls_addr
                        ),
                    },
                },
            )
        }
        None => None,
    };

    // The secondaries are rows: a database that did not answer is not asked
    // for them again.
    let (secondaries, notifies, transfers) = if database.status == DoctorCheckStatus::Failed {
        (Vec::new(), Vec::new(), Vec::new())
    } else {
        // Capture secondary serials before the NOTIFY check can trigger a refresh.
        let secondaries =
            probe::probe_secondaries(cx, &config.dns.catalog_zone_name, catalog_serial).await?;
        // Actively test NOTIFY delivery; this can prompt secondaries to transfer the catalog.
        let notifies =
            notify::send_notify_to_secondaries(cx, &config.dns.catalog_zone_name).await?;
        let mut transfers = Vec::new();
        for secondary in secondary::list_enabled(cx).await? {
            transfers.push(SecondaryTransferSummary {
                summary: secondary::transfer_summary(cx, &secondary).await?,
                secondary_name: secondary.name,
                address: secondary.address.to_string(),
            });
        }
        (secondaries, notifies, transfers)
    };

    let response = DaemonDoctorResponse {
        database,
        dns_server,
        dns_tls_server,
        catalog_zone_name: config.dns.catalog_zone_name.to_string(),
        catalog_serial,
        secondaries,
        notifies,
        transfers,
    };

    Ok(DaemonResponse {
        message: "Doctor checks completed".to_string(),
        data: response,
    })
}
