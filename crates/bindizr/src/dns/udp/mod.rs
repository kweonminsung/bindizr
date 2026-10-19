//! The UDP listener: one datagram in, one answer out; a transfer is sent on
//! to TCP.

#[cfg(test)]
mod tests;

use std::{
    future::Future,
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::Arc,
};

use bindizr_core::dns::message::{
    self, Class, ExtendedErrorCode, Keepalive, Opcode, OptRcode, Rtype,
};
use nix::{
    libc::{in_addr, in_pktinfo, in6_addr, in6_pktinfo},
    sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg,
        setsockopt, sockopt,
    },
};
use thiserror::Error;
use tokio::{io::Interest, sync::Semaphore};

use super::server::{self, DnsContext};

/// Datagrams answered at once; past this the listener drops, since a caller retries.
const MAX_UDP_IN_FLIGHT: usize = 256;

/// The UDP socket and packet metadata needed to preserve the queried address.
#[derive(Debug)]
pub(crate) struct UdpSocket {
    socket: tokio::net::UdpSocket,
}

/// A received peer and the local destination to use for its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplyTarget {
    pub(crate) client_addr: SocketAddr,
    local_ip: IpAddr,
    interface_index: u32,
}

/// A UDP I/O failure or a datagram whose reply address cannot be preserved.
#[derive(Debug, Error)]
enum UdpError {
    #[error("UDP I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("UDP datagram or packet metadata was truncated")]
    Truncated,
    #[error("UDP datagram has no IP peer address")]
    MissingPeer,
    #[error("UDP datagram has no local destination address")]
    MissingDestination,
}

impl UdpSocket {
    /// Enable per-packet addressing before the listener starts receiving.
    pub(crate) fn new(socket: tokio::net::UdpSocket) -> io::Result<Self> {
        if socket.local_addr()?.is_ipv6() {
            setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &true)?;
        } else {
            setsockopt(&socket, sockopt::Ipv4PacketInfo, &true)?;
        }
        Ok(Self { socket })
    }

    /// Receive a complete datagram together with its peer and local destination.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, ReplyTarget), UdpError> {
        let (len, flags, peer, destination) = self
            .socket
            .async_io(Interest::READABLE, || {
                let mut iov = [IoSliceMut::new(buf)];
                let mut control = nix::cmsg_space!(in_pktinfo, in6_pktinfo);
                let message = recvmsg::<SockaddrStorage>(
                    self.socket.as_raw_fd(),
                    &mut iov,
                    Some(&mut control),
                    MsgFlags::empty(),
                )?;
                let mut destination = None;
                if !message
                    .flags
                    .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                {
                    for control in message.cmsgs()? {
                        match control {
                            ControlMessageOwned::Ipv4PacketInfo(info) => {
                                destination = Some((
                                    IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())),
                                    0,
                                ));
                            }
                            ControlMessageOwned::Ipv6PacketInfo(info) => {
                                destination = Some((
                                    IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                                    info.ipi6_ifindex,
                                ));
                            }
                            _ => {}
                        }
                    }
                }
                Ok((message.bytes, message.flags, message.address, destination))
            })
            .await?;
        if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
            return Err(UdpError::Truncated);
        }
        let client_addr = peer
            .and_then(|peer| {
                peer.as_sockaddr_in()
                    .map(|addr| SocketAddr::from(*addr))
                    .or_else(|| peer.as_sockaddr_in6().map(|addr| SocketAddr::from(*addr)))
            })
            .ok_or(UdpError::MissingPeer)?;
        let (local_ip, interface_index) = destination.ok_or(UdpError::MissingDestination)?;
        Ok((
            len,
            ReplyTarget {
                client_addr,
                local_ip,
                interface_index,
            },
        ))
    }

    /// Reply from the query's destination IP and the listener's bound port.
    pub(crate) async fn send_to(&self, response: &[u8], target: ReplyTarget) -> io::Result<usize> {
        let peer = SockaddrStorage::from(target.client_addr);
        self.socket
            .async_io(Interest::WRITABLE, || {
                let ipv4;
                let ipv6;
                // IPv4-mapped peers need IPv4 source selection on macOS too.
                let control = match target.local_ip.to_canonical() {
                    IpAddr::V4(ip) => {
                        // Use the queried IP (RFC 2181, Section 4.1); routing chooses the interface.
                        ipv4 = in_pktinfo {
                            ipi_ifindex: 0,
                            ipi_spec_dst: in_addr {
                                s_addr: u32::from_ne_bytes(ip.octets()),
                            },
                            ipi_addr: in_addr { s_addr: 0 },
                        };
                        ControlMessage::Ipv4PacketInfo(&ipv4)
                    }
                    IpAddr::V6(ip) => {
                        ipv6 = in6_pktinfo {
                            ipi6_addr: in6_addr {
                                s6_addr: ip.octets(),
                            },
                            ipi6_ifindex: target.interface_index,
                        };
                        ControlMessage::Ipv6PacketInfo(&ipv6)
                    }
                };
                sendmsg(
                    self.socket.as_raw_fd(),
                    &[IoSlice::new(response)],
                    &[control],
                    MsgFlags::empty(),
                    Some(&peer),
                )
                .map_err(io::Error::from)
            })
            .await
    }
}

/// Receive and dispatch DNS UDP datagrams until shutdown.
pub(crate) async fn run_udp_server(
    dns_cx: Arc<DnsContext>,
    socket: UdpSocket,
    stop: impl Future<Output = ()>,
) {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    // The extra byte distinguishes an oversized/truncated datagram from a full DNS message.
    let mut buf = vec![0u8; usize::from(u16::MAX) + 1];
    tokio::pin!(stop);

    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buf) => received,
            () = &mut stop => {
                log::info!("DNS UDP server stopping");
                return;
            }
        };

        let (len, target) = match received {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to receive DNS UDP packet: {}", e);
                continue;
            }
        };
        let client_addr = target.client_addr;

        if len == buf.len() {
            log::warn!("Dropping oversized DNS UDP query from {}", client_addr);
            continue;
        }
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            log::warn!("Dropping excess DNS UDP query from {}", client_addr);
            continue;
        };
        let query_data = buf[..len].to_vec();
        let socket = socket.clone();
        let dns_cx = dns_cx.clone();
        tokio::spawn(async move {
            handle_udp_query(&dns_cx, &socket, target, &query_data).await;
            drop(permit);
        });
    }
}

/// Dispatch UDP UPDATE, SOA, and XFR queries, refusing unsupported query types.
async fn handle_udp_query(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    target: ReplyTarget,
    query_data: &[u8],
) {
    let client_addr = target.client_addr;
    if message::is_response(query_data) {
        log::warn!("Ignoring a DNS UDP response from {}", client_addr);
        return;
    }

    if server::nsupdate::is_nsupdate(query_data) {
        if let Err(e) =
            server::nsupdate::handle_udp_nsupdate(dns_cx, socket, query_data, target).await
        {
            log::error!("NSUPDATE UDP handler failed for {}: {}", client_addr, e);
        }
        return;
    }

    let query = match message::ParsedQuery::parse(query_data, Keepalive::None) {
        Ok(query) => query,
        Err(error) => {
            if let Some(response) = error.to_response() {
                send_udp_response(socket, target, &response).await;
            }
            return;
        }
    };

    // Each refusal below is answered under the query's key when it has one.
    let refusal = if let Some(rcode) = query.format_error() {
        log::info!(
            "Refusing DNS UDP query format from {}: {}",
            client_addr,
            rcode
        );
        Some((rcode, None))
    } else if query.qclass != Class::IN {
        // RFC 5936, Section 2.2.2 echoes the class asked; only IN is served.
        log::info!(
            "Refusing DNS UDP class {} from {}",
            query.qclass,
            client_addr
        );
        Some((
            OptRcode::NOTAUTH,
            Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
        ))
    } else if query.opcode != Opcode::QUERY {
        log::info!(
            "Refusing DNS UDP opcode {:?} from {}",
            query.opcode,
            client_addr
        );
        Some((OptRcode::NOTIMP, Some(ExtendedErrorCode::NOT_SUPPORTED)))
    } else {
        None
    };
    if let Some((rcode, ede)) = refusal {
        match server::refuse_query(dns_cx, &query, query_data, rcode, ede).await {
            Ok(response) => send_udp_response(socket, target, &response).await,
            Err(e) => log::warn!("Failed to refuse DNS UDP query from {}: {}", client_addr, e),
        }
        return;
    }

    if query.qtype == Rtype::SOA {
        if let Err(e) =
            server::soa::handle_udp_soa(dns_cx, socket, target, &query, query_data).await
        {
            log::warn!("Failed to handle SOA UDP query from {}: {}", client_addr, e);
        }
        return;
    }

    // RFC 1995, Section 2: return only the current SOA; lagging clients retry over TCP.
    if query.qtype == Rtype::IXFR {
        if let Err(e) =
            server::soa::handle_udp_ixfr(dns_cx, socket, target, &query, query_data).await
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
        match server::handle_udp_xfr(dns_cx, client_addr, &query, query_data).await {
            Ok(response) => response,
            Err(error) => {
                log::warn!(
                    "Failed to answer DNS UDP transfer from {}: {}",
                    client_addr,
                    error
                );
                return;
            }
        }
    } else {
        log::info!(
            "Refusing out-of-scope DNS UDP query from {} (qtype={:?})",
            client_addr,
            query.qtype
        );
        match server::refuse_query(
            dns_cx,
            &query,
            query_data,
            OptRcode::REFUSED,
            Some(ExtendedErrorCode::NOT_SUPPORTED),
        )
        .await
        {
            Ok(response) => response,
            Err(e) => {
                log::warn!("Failed to refuse DNS UDP query from {}: {}", client_addr, e);
                return;
            }
        }
    };
    send_udp_response(socket, target, &response).await;
}

/// Send a DNS response datagram to the requesting peer.
async fn send_udp_response(socket: &UdpSocket, target: ReplyTarget, response: &[u8]) {
    if let Err(e) = socket.send_to(response, target).await {
        log::warn!(
            "Failed to answer DNS UDP query from {}: {}",
            target.client_addr,
            e
        );
    }
}
