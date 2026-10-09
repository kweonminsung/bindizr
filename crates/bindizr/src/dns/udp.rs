//! The UDP listener: one datagram in, one answer out; a transfer is sent on
//! to TCP.

use std::{future::Future, net::SocketAddr, sync::Arc};

use bindizr_core::dns::message::{self, Class, ExtendedErrorCode, Keepalive, Opcode, Rcode, Rtype};
use tokio::{net::UdpSocket, sync::Semaphore};

use super::server::{self, DnsContext};

/// Datagrams answered at once; past this the listener drops, since a caller retries.
const MAX_UDP_IN_FLIGHT: usize = 256;

/// Receive and dispatch DNS UDP datagrams until shutdown.
pub(crate) async fn run_udp_server(
    dns_cx: Arc<DnsContext>,
    socket: UdpSocket,
    stop: impl Future<Output = ()>,
) {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    let mut buf = vec![0u8; 65535];
    tokio::pin!(stop);

    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buf) => received,
            () = &mut stop => {
                log::info!("DNS UDP server stopping");
                return;
            }
        };

        let (len, client_addr) = match received {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to receive DNS UDP packet: {}", e);
                continue;
            }
        };

        // Drop excess datagrams instead of queuing work; each handler holds its
        // permit until dispatch finishes.
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            log::warn!(
                "Dropping DNS UDP query from {}: {} already in flight",
                client_addr,
                MAX_UDP_IN_FLIGHT
            );
            continue;
        };

        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let dns_cx = dns_cx.clone();
        tokio::spawn(async move {
            dispatch_udp_query(&dns_cx, &socket, client_addr, &query_data).await;
            drop(permit);
        });
    }
}

/// Dispatch UDP UPDATE, SOA, and XFR queries, refusing unsupported query types.
async fn dispatch_udp_query(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    client_addr: SocketAddr,
    query_data: &[u8],
) {
    if message::is_response(query_data) {
        log::warn!("Ignoring a DNS UDP response from {}", client_addr);
        return;
    }

    if server::nsupdate::is_nsupdate(query_data) {
        if let Err(e) =
            server::nsupdate::handle_udp_nsupdate(dns_cx, socket, query_data, client_addr).await
        {
            log::error!("NSUPDATE UDP handler failed for {}: {}", client_addr, e);
        }
        return;
    }

    let Ok(query) = message::ParsedQuery::parse(query_data, Keepalive::None) else {
        return;
    };

    if let Some(response) = query.edns_error_response() {
        log::info!("Refusing the EDNS of a DNS UDP query from {}", client_addr);
        send_udp_response(socket, client_addr, &response).await;
        return;
    }

    // RFC 5936, Section 2.2.2 echoes the class asked; only IN is served.
    if query.qclass != Class::IN {
        log::info!(
            "Refusing DNS UDP class {} from {}",
            query.qclass,
            client_addr
        );
        let response =
            query.error_response(Rcode::NOTAUTH, Some(ExtendedErrorCode::NOT_AUTHORITATIVE));
        send_udp_response(socket, client_addr, &response).await;
        return;
    }

    if query.opcode != Opcode::QUERY {
        log::info!(
            "Refusing DNS UDP opcode {:?} from {}",
            query.opcode,
            client_addr
        );
        let response = query.error_response(Rcode::NOTIMP, Some(ExtendedErrorCode::NOT_SUPPORTED));
        send_udp_response(socket, client_addr, &response).await;
        return;
    }

    if query.qtype == Rtype::SOA {
        if let Err(e) =
            server::soa::handle_udp_soa(dns_cx, socket, client_addr, &query, query_data).await
        {
            log::warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
        }
        return;
    }

    // RFC 1995, Section 2: a UDP IXFR gets the current SOA alone, sending a
    // client that is behind to TCP; Windows DNS asks this way after NOTIFY.
    if query.qtype == Rtype::IXFR {
        if let Err(e) =
            server::soa::handle_udp_ixfr(dns_cx, socket, client_addr, &query, query_data).await
        {
            log::warn!(
                "Failed to handle IXFR UDP query from {}: {}",
                client_addr,
                e
            );
        }
        return;
    }

    let response = if server::is_xfr_query_type(query.qtype) {
        server::handle_udp_xfr(dns_cx, client_addr, &query, query_data).await
    } else {
        log::info!(
            "Refusing out-of-scope DNS UDP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
        query.error_response(Rcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED))
    };
    send_udp_response(socket, client_addr, &response).await;
}

/// Send a DNS response datagram to the requesting peer.
async fn send_udp_response(socket: &UdpSocket, client_addr: SocketAddr, response: &[u8]) {
    if let Err(e) = socket.send_to(response, client_addr).await {
        log::warn!("Failed to answer DNS UDP query from {}: {}", client_addr, e);
    }
}
