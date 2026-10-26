//! The UDP listener: one datagram in, one answer out; a transfer is sent on
//! to TCP.

#[cfg(test)]
mod tests;

use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bindizr_core::dns::message::{self, Keepalive, ResponseLimit, Rtype};
use bindizr_core::model::transfer::TransferTransport;
use nix::libc::{in_addr, in_pktinfo, in6_addr, in6_pktinfo};
use nix::sys::socket;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, sockopt};
use thiserror::Error;
use tokio::io::Interest;
use tokio::task::JoinSet;

use super::error::DnsError;
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
            socket::setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &true)?;
        } else {
            socket::setsockopt(&socket, sockopt::Ipv4PacketInfo, &true)?;
        }
        Ok(Self { socket })
    }

    /// Receive a complete datagram together with its peer and local destination.
    async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, ReplyTarget), UdpError> {
        let (len, flags, peer, destination) = self
            .socket
            .async_io(Interest::READABLE, || {
                let mut iov = [IoSliceMut::new(buffer)];
                let mut control = nix::cmsg_space!(in_pktinfo, in6_pktinfo);
                let message = socket::recvmsg::<SockaddrStorage>(
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
    pub(crate) async fn send_to(
        &self,
        response: &[u8],
        target: ReplyTarget,
        limit: ResponseLimit,
    ) -> Result<usize, DnsError> {
        limit.validate_len(response.len())?;
        let peer = SockaddrStorage::from(target.client_addr);

        Ok(self
            .socket
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

                socket::sendmsg(
                    self.socket.as_raw_fd(),
                    &[IoSlice::new(response)],
                    &[control],
                    MsgFlags::empty(),
                    Some(&peer),
                )
                .map_err(io::Error::from)
            })
            .await?)
    }
}

/// Receive and dispatch DNS UDP datagrams until shutdown.
pub(crate) async fn run_udp_server(
    dns_cx: Arc<DnsContext>,
    socket: UdpSocket,
    stop: impl Future<Output = ()>,
) {
    let socket = Arc::new(socket);
    let mut in_flight = JoinSet::new();

    // The extra byte distinguishes an oversized/truncated datagram from a full DNS message.
    let mut buffer = vec![0u8; usize::from(u16::MAX) + 1];
    tokio::pin!(stop);

    loop {
        let received = tokio::select! {
            biased;
            () = &mut stop => {
                log::info!("DNS UDP server stopping");
                break;
            }

            Some(result) = in_flight.join_next(), if !in_flight.is_empty() => {
                if let Err(error) = result {
                    log::warn!("DNS UDP query task failed: {}", error);
                }
                continue;
            }

            received = socket.recv_from(&mut buffer) => received,
        };

        let (len, target) = match received {
            Ok(received) => received,
            Err(error) => {
                log::error!("Failed to receive DNS UDP packet: {}", error);
                continue;
            }
        };
        let client_addr = target.client_addr;

        if len == buffer.len() {
            log::warn!("Dropping oversized DNS UDP query from {}", client_addr);
            continue;
        }
        if in_flight.len() >= MAX_UDP_IN_FLIGHT {
            log::warn!("Dropping excess DNS UDP query from {}", client_addr);
            continue;
        }

        let query_data = buffer[..len].to_vec();
        let socket = socket.clone();
        let dns_cx = dns_cx.clone();

        in_flight.spawn(async move {
            handle_udp_query(&dns_cx, &socket, target, &query_data).await;
        });
    }

    while let Some(result) = in_flight.join_next().await {
        if let Err(error) = result {
            log::warn!("DNS UDP query task failed: {}", error);
        }
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
        if let Err(error) =
            server::nsupdate::handle_udp_nsupdate(dns_cx, socket, query_data, target).await
        {
            log::error!("NSUPDATE UDP handler failed for {}: {}", client_addr, error);
        }
        return;
    }

    match server::refuse_unsupported_opcode(
        dns_cx,
        query_data,
        Keepalive::None,
        TransferTransport::Udp,
    )
    .await
    {
        Ok(Some((response, limit))) => {
            send_udp_response(socket, target, &response, limit).await;
            return;
        }
        Ok(None) => {}
        Err(error) => {
            log::warn!(
                "Failed to refuse DNS UDP opcode from {}: {}",
                client_addr,
                error
            );
            return;
        }
    }

    let query = match message::ParsedQuery::parse(query_data, Keepalive::None) {
        Ok(query) => query,
        Err(error) => {
            if let Some(metadata) = error.query_metadata() {
                let rcode = metadata
                    .format_error()
                    .unwrap_or(message::OptRcode::FORMERR);

                match server::refuse_query(dns_cx, metadata, query_data, rcode, None).await {
                    Ok(response) => {
                        send_udp_response(socket, target, &response, metadata.response_limit())
                            .await
                    }
                    Err(error) => log::warn!(
                        "Failed to answer malformed DNS UDP query from {}: {}",
                        client_addr,
                        error
                    ),
                }
            }

            return;
        }
    };

    if let Some((rcode, ede)) = server::query_refusal(&query, TransferTransport::Udp, client_addr) {
        match server::refuse_query(
            dns_cx,
            &message::QueryMetadata::from(&query),
            query_data,
            rcode,
            ede,
        )
        .await
        {
            Ok(response) => {
                send_udp_response(socket, target, &response, query.response_limit()).await
            }
            Err(error) => log::warn!(
                "Failed to refuse DNS UDP query from {}: {}",
                client_addr,
                error
            ),
        }

        return;
    }

    if query.qtype == Rtype::SOA {
        if let Err(error) =
            server::soa::handle_udp_soa(dns_cx, socket, target, &query, query_data).await
        {
            log::warn!(
                "Failed to handle SOA UDP query from {}: {}",
                client_addr,
                error
            );
        }

        return;
    }

    // RFC 1995, Section 2: return only the current SOA; lagging clients retry over TCP.
    if query.qtype == Rtype::IXFR {
        if let Err(error) =
            server::soa::handle_udp_ixfr(dns_cx, socket, target, &query, query_data).await
        {
            log::warn!(
                "Failed to handle IXFR UDP query from {}: {}",
                client_addr,
                error
            );
        }

        return;
    }

    if let Err(error) = server::handle_udp_xfr(dns_cx, socket, target, &query, query_data).await {
        log::warn!(
            "Failed to answer DNS UDP transfer from {}: {}",
            client_addr,
            error
        );
    }
}

/// Send a DNS response datagram to the requesting peer.
async fn send_udp_response(
    socket: &UdpSocket,
    target: ReplyTarget,
    response: &[u8],
    limit: ResponseLimit,
) {
    if let Err(error) = socket.send_to(response, target, limit).await {
        log::warn!(
            "Failed to answer DNS UDP query from {}: {}",
            target.client_addr,
            error
        );
    }
}
