//! DNS front end: the TCP, UDP, and XoT listeners, plus zone transfer
//! (AXFR/IXFR), NOTIFY, SOA queries, RFC 2136 nsupdate, and secondary ACLs.

pub(crate) mod error;
pub(crate) mod server;
mod stream;
mod tcp;
mod tls;
mod udp;
pub(crate) mod wire;

use std::{net::SocketAddr, sync::Arc};

use bindizr_service::Context;
use thiserror::Error;
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

use self::{server::DnsContext, tcp::Handshake};
use crate::{shutdown::Shutdown, tls::TlsCertificate};

/// Why a DNS listener could not come up.
#[derive(Debug, Error)]
pub(crate) enum StartDnsError {
    /// Names the usual cause when the port is already taken.
    #[error("failed to bind DNS {socket} on {addr}: {source}{}", if source.kind() == std::io::ErrorKind::AddrInUse { format!(" (another DNS server on this host? change {setting})") } else { String::new() })]
    Bind {
        socket: &'static str,
        addr: SocketAddr,
        /// The configuration key that moves this listener.
        setting: &'static str,
        #[source]
        source: std::io::Error,
    },
}

/// The DNS front end's accept loops, for the daemon to supervise.
#[derive(Debug)]
pub(crate) struct DnsServers {
    pub(crate) tcp: JoinHandle<()>,
    pub(crate) udp: JoinHandle<()>,
    /// Present when `dns.tls` names a certificate.
    pub(crate) tls: Option<JoinHandle<()>>,
}

/// Bring the DNS front end up: prepare the catalog zone and spawn the TCP,
/// UDP, and (with a certificate) TLS servers, handing back their accept loops.
pub(crate) async fn initialize(
    cx: Arc<Context>,
    shutdown: &Shutdown,
    certificate: Option<Arc<TlsCertificate>>,
) -> Result<DnsServers, StartDnsError> {
    let dns_cx = Arc::new(DnsContext::new(cx.clone()));

    // The catalog zone must exist before a secondary asks for it.
    let catalog = match bindizr_service::zone::list(&cx).await {
        Ok(zones) => server::catalog::generate_catalog_zone(&dns_cx, zones).await,
        Err(e) => Err(e.into()),
    };
    match catalog {
        Ok((catalog, _)) => {
            log::info!(
                "Catalog zone '{}' is ready (serial: {})",
                cx.config().dns.catalog_zone_name,
                catalog.serial
            );
        }
        Err(e) => {
            log::warn!("Failed to generate catalog zone: {}", e);
        }
    }

    let config = cx.config();
    let listen_addr = SocketAddr::new(config.dns.listen_addr, config.dns.listen_port);

    let tcp_listener =
        TcpListener::bind(listen_addr)
            .await
            .map_err(|source| StartDnsError::Bind {
                socket: "TCP listener",
                addr: listen_addr,
                setting: "dns.listen_port",
                source,
            })?;
    let udp_socket = UdpSocket::bind(listen_addr)
        .await
        .map_err(|source| StartDnsError::Bind {
            socket: "UDP socket",
            addr: listen_addr,
            setting: "dns.listen_port",
            source,
        })?;
    // Bound before anything serves, so a failure exits the start.
    let tls_listener = match certificate {
        Some(certificate) => {
            let tls_addr = SocketAddr::new(config.dns.listen_addr, config.dns.tls.listen_port);
            let server_config = tls::build_server_config(certificate);
            let listener =
                TcpListener::bind(tls_addr)
                    .await
                    .map_err(|source| StartDnsError::Bind {
                        socket: "TLS listener",
                        addr: tls_addr,
                        setting: "dns.tls.listen_port",
                        source,
                    })?;
            Some((tls_addr, listener, server_config))
        }
        None => None,
    };

    log::info!("DNS TCP server listening on {}", listen_addr);
    log::info!("DNS UDP server listening on {}", listen_addr);

    let tcp_stop = shutdown.waiter();
    let tcp_cx = dns_cx.clone();
    let tcp_task = tokio::spawn(async move {
        if let Err(e) = tcp::run_tcp_server(tcp_cx, tcp_listener, Handshake::None, tcp_stop).await {
            log::error!("DNS TCP server error: {}", e);
        }
    });

    let tls_task = tls_listener.map(|(tls_addr, listener, server_config)| {
        log::info!("DNS TLS server listening on {} (XoT)", tls_addr);
        let tls_stop = shutdown.waiter();
        let tls_cx = dns_cx.clone();
        tokio::spawn(async move {
            if let Err(e) =
                tcp::run_tcp_server(tls_cx, listener, Handshake::Tls(server_config), tls_stop).await
            {
                log::error!("DNS TLS server error: {}", e);
            }
        })
    });

    let udp_stop = shutdown.waiter();
    let udp_cx = dns_cx;
    let udp_task = tokio::spawn(udp::run_udp_server(udp_cx, udp_socket, udp_stop));

    Ok(DnsServers {
        tcp: tcp_task,
        udp: udp_task,
        tls: tls_task,
    })
}
