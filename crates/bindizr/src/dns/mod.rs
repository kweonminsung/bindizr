//! DNS front end: the TCP, UDP, and XoT listeners, plus zone transfer
//! (AXFR/IXFR), SOA queries, RFC 2136 nsupdate, and secondary ACLs.

mod connection;
pub(crate) mod error;
pub(crate) mod server;
mod stream;
mod tcp;
mod tls;
mod udp;
pub(crate) mod wire;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bindizr_service::Context;
use thiserror::Error;
use tokio::net;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::dns::server::DnsContext;
use crate::dns::udp::UdpSocket;
use crate::shutdown::Shutdown;
use crate::tls::TlsCertificate;

/// Why a DNS listener could not come up.
#[derive(Debug, Error)]
pub(crate) enum StartDnsError {
    #[error("failed to enable DNS UDP packet information: {0}")]
    UdpPacketInfo(#[source] io::Error),
    /// Names the usual cause when the port is already taken.
    #[error("failed to bind DNS {socket} on {addr}: {source}{}", if source.kind() == io::ErrorKind::AddrInUse {
        format!(" (another DNS server on this host? change {setting})")
    } else {
        String::new()
    })]
    Bind {
        socket: &'static str,
        addr: SocketAddr,
        /// The configuration key that moves this listener.
        setting: &'static str,
        #[source]
        source: io::Error,
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

/// Bring the DNS front end up: spawn the TCP, UDP, and (with a certificate)
/// TLS servers, handing back their accept loops. The catalog zone is built
/// from the zones each time a secondary asks for it.
pub(crate) async fn start(
    cx: Arc<Context>,
    shutdown: &Shutdown,
    certificate: Option<Arc<TlsCertificate>>,
) -> Result<DnsServers, StartDnsError> {
    let dns_cx = Arc::new(DnsContext::new(cx.clone()));

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
    let udp_socket =
        net::UdpSocket::bind(listen_addr)
            .await
            .map_err(|source| StartDnsError::Bind {
                socket: "UDP socket",
                addr: listen_addr,
                setting: "dns.listen_port",
                source,
            })?;
    let udp_socket = UdpSocket::new(udp_socket).map_err(StartDnsError::UdpPacketInfo)?;

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

    log::info!("DNS TCP server listening on {listen_addr}");
    log::info!("DNS UDP server listening on {listen_addr}");

    let tcp_stop = shutdown.waiter();
    let tcp_task = {
        let dns_cx = dns_cx.clone();

        tokio::spawn(async move {
            if let Err(error) = tcp::run_tcp_server(dns_cx, tcp_listener, tcp_stop).await {
                log::error!("DNS TCP server error: {error}");
            }
        })
    };

    let tls_task = tls_listener.map(|(tls_addr, listener, server_config)| {
        log::info!("DNS TLS server listening on {tls_addr} (XoT)");
        let tls_stop = shutdown.waiter();
        let dns_cx = dns_cx.clone();

        tokio::spawn(async move {
            if let Err(error) = tls::run_tls_server(dns_cx, listener, server_config, tls_stop).await
            {
                log::error!("DNS TLS server error: {error}");
            }
        })
    });

    let udp_stop = shutdown.waiter();
    let udp_task = tokio::spawn(udp::run_udp_server(dns_cx, udp_socket, udp_stop));

    Ok(DnsServers {
        tcp: tcp_task,
        udp: udp_task,
        tls: tls_task,
    })
}
