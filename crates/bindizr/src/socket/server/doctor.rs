use std::net::SocketAddr;

use bindizr_core::dns::address::loopback_if_unspecified;
use bindizr_service::{
    Context, authorization::Caller, dns_client, error::ServiceError, secondary,
    types::CheckSecondariesResponse, zone,
};
use tokio::net::TcpStream;

use crate::{
    daemon::db_probe::DB_PROBE_TIMEOUT,
    socket::types::{DaemonDoctorResponse, DaemonResponse, DoctorCheckResponse, DoctorCheckStatus},
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
        Ok(Ok(total)) => DoctorCheckResponse {
            status: DoctorCheckStatus::Ok,
            message: format!(
                "Database connected: {} ({} zones)",
                config.database.database_type, total
            ),
        },
        Ok(Err(error)) => DoctorCheckResponse {
            status: DoctorCheckStatus::Failed,
            message: format!("Database not reachable: {}", error),
        },
        Err(_) => DoctorCheckResponse {
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
        match dns_client::probe::probe_server(dns_addr, &config.dns.catalog_zone_name, timeout)
            .await
        {
            Ok(serial) => (
                DoctorCheckResponse {
                    status: DoctorCheckStatus::Ok,
                    message: format!(
                        "DNS server reachable: {} (catalog zone {} at serial {})",
                        dns_addr, config.dns.catalog_zone_name, serial
                    ),
                },
                Some(serial),
            ),
            Err(error) => (
                DoctorCheckResponse {
                    status: DoctorCheckStatus::Failed,
                    message: format!("DNS server not reachable: {}: {}", dns_addr, error),
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
                    Ok(Ok(_)) => DoctorCheckResponse {
                        status: DoctorCheckStatus::Ok,
                        message: format!(
                            "DNS TLS server listening: {} (TLS handshake not attempted)",
                            dns_tls_addr
                        ),
                    },
                    Ok(Err(error)) => DoctorCheckResponse {
                        status: DoctorCheckStatus::Failed,
                        message: format!(
                            "DNS TLS server not reachable: {}: {}",
                            dns_tls_addr, error
                        ),
                    },
                    Err(_) => DoctorCheckResponse {
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
    let diagnostics = if database.status == DoctorCheckStatus::Failed {
        CheckSecondariesResponse::default()
    } else {
        secondary::check_enabled(cx, &caller, &config.dns.catalog_zone_name, catalog_serial).await?
    };

    let response = DaemonDoctorResponse {
        database,
        dns_server,
        dns_tls_server,
        catalog_zone_name: config.dns.catalog_zone_name.to_string(),
        catalog_serial,
        secondaries: diagnostics.secondaries,
        notifies: diagnostics.notifies,
        transfers: diagnostics.transfers,
    };

    Ok(DaemonResponse {
        message: "Doctor checks completed".to_string(),
        data: response,
    })
}
