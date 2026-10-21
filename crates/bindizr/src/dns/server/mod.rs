//! Inbound DNS serving: AXFR/IXFR dispatch with TSIG or ACL gating, SOA
//! responses, catalog-zone generation, and RFC 2136 nsupdate handling.

use bindizr_core::dns::message;

pub(crate) mod acl;
pub(crate) mod auth;
pub(crate) mod axfr;
pub(crate) mod catalog;
pub(crate) mod ixfr;
pub(crate) mod nsupdate;
pub(crate) mod soa;
pub(crate) mod transfer_cache;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub(crate) use auth::refuse_query;
use auth::{TransferRefusal, authenticate_transfer, authorize_transport};
use bindizr_core::{
    dns::message::{Class, ExtendedErrorCode, Opcode, OptRcode, Rtype},
    metrics::XfrResult,
    model::transfer::{TransferKind, TransferTransport},
};
use bindizr_service::{Context, transfer};

use crate::dns::{
    error::DnsError,
    stream::ResponseWriter,
    udp::{ReplyTarget, UdpSocket},
};

/// DNS-specific caches and daemon context; handlers take `dns_cx` and derive `cx`.
#[derive(Debug)]
pub(crate) struct DnsContext {
    daemon: Arc<Context>,
    pub(crate) transfer_cache: transfer_cache::TransferCache,
    pub(crate) address_cache: acl::AddressCache,
}

impl DnsContext {
    /// The front end's context over the daemon's, with empty caches.
    pub(crate) fn new(daemon: Arc<Context>) -> Self {
        DnsContext {
            daemon,
            transfer_cache: transfer_cache::TransferCache::new(),
            address_cache: acl::AddressCache::new(),
        }
    }

    /// The daemon's context.
    pub(crate) fn daemon(&self) -> &Arc<Context> {
        &self.daemon
    }
}

/// Check whether a query type requests AXFR or IXFR.
pub(crate) fn is_xfr_query_type(qtype: Rtype) -> bool {
    matches!(qtype, Rtype::AXFR | Rtype::IXFR)
}

/// Classify unsupported opcodes from the header, including opaque request bodies.
pub(crate) async fn refuse_unsupported_opcode(
    dns_cx: &DnsContext,
    query_data: &[u8],
    keepalive: message::Keepalive,
    transport: TransferTransport,
) -> Result<Option<(Vec<u8>, message::ResponseLimit)>, DnsError> {
    let Some(opcode) = message::extract_opcode(query_data) else {
        return Ok(None);
    };

    if opcode == Opcode::QUERY || opcode == Opcode::UPDATE {
        return Ok(None);
    }

    let Ok(metadata) = message::QueryMetadata::parse(query_data, keepalive) else {
        return Ok(None);
    };
    let (rcode, ede) = if let Some(rcode) = metadata.format_error() {
        (rcode, None)
    } else if transport == TransferTransport::Tls {
        (OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED))
    } else {
        (OptRcode::NOTIMP, Some(ExtendedErrorCode::NOT_SUPPORTED))
    };

    let response = refuse_query(dns_cx, &metadata, query_data, rcode, ede).await?;

    Ok(Some((response, metadata.response_limit())))
}

/// Classify malformed queries and transport-specific refusals before dispatch.
pub(crate) fn query_refusal(
    query: &message::ParsedQuery,
    transport: TransferTransport,
    client_addr: SocketAddr,
) -> Option<(OptRcode, Option<ExtendedErrorCode>)> {
    if let Some(rcode) = query.format_error() {
        log::info!(
            "Refusing DNS {} query format from {}: {}",
            transport,
            client_addr,
            rcode
        );
        return Some((rcode, None));
    }

    // RFC 9103, Section 7.8: refuse non-XoT traffic regardless of its class.
    if transport == TransferTransport::Tls
        && query.qtype != Rtype::SOA
        && !is_xfr_query_type(query.qtype)
    {
        log::info!(
            "Refusing unsupported TLS query from {} (opcode={:?}, qtype={:?})",
            client_addr,
            query.opcode,
            query.qtype
        );
        return Some((OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED)));
    }
    if query.qclass != Class::IN {
        // Only IN is served; the question, class included, is copied into the
        // response (RFC 5936, Section 2.2.2).
        log::info!(
            "Refusing DNS {} class {} from {}",
            transport,
            query.qclass,
            client_addr
        );
        return Some((
            OptRcode::NOTAUTH,
            Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
        ));
    }
    if query.qtype != Rtype::SOA && !is_xfr_query_type(query.qtype) {
        log::info!(
            "Refusing out-of-scope DNS {} query from {} (qtype={:?})",
            transport,
            client_addr,
            query.qtype
        );
        return Some((OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED)));
    }

    None
}

/// Authenticate and serve a TCP zone transfer, returning refusals as DNS responses.
/// Count by the requested type so an IXFR falling back to AXFR still counts as IXFR.
pub(crate) async fn handle_tcp_xfr(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();
    let client_ip = client_addr.ip();
    let transport = writer.transport();
    let track_result = |result| cx.metrics().track_xfr(query.qtype, transport, result);

    // Zone grants are checked with the zone row; check key/address and transport here.
    let identity = tokio::select! {
        biased;
        () = writer.failed() => return Err(DnsError::PeerClosed),

        result = authenticate_transfer(dns_cx, query_data, client_ip, transport) => result,
    }
    .and_then(|identity| authorize_transport(dns_cx, transport, identity));

    let mut identity = match identity {
        Ok(identity) => identity,
        Err(refusal) => {
            return refuse_tcp_xfr(dns_cx, writer, client_ip, query, query_data, refusal).await;
        }
    };

    log::info!(
        "XFR {} query: zone={:?}, qtype={:?}, from={}, signed={}",
        transport,
        query.zone_name,
        query.qtype,
        client_ip,
        identity.signer.is_some()
    );

    let result = match query.qtype {
        Rtype::AXFR => {
            axfr::handle_axfr(dns_cx, writer, query, client_ip, Rtype::AXFR, &mut identity).await
        }
        Rtype::IXFR => ixfr::handle_ixfr(dns_cx, writer, query, client_ip, &mut identity).await,
        _ => {
            log::warn!("Unsupported query type: {:?}", query.qtype);
            return Err(DnsError::InvalidQuery(format!(
                "Unsupported query type: {:?}",
                query.qtype
            )));
        }
    };

    // A missing zone gets NOTAUTH and an ungranted one REFUSED, both under the
    // key that asked; other transfer failures propagate to the listener.
    match result {
        Ok(()) => {
            track_result(XfrResult::Ok);
            Ok(())
        }
        Err(DnsError::NotAuth(reason)) => {
            refuse_tcp_xfr(
                dns_cx,
                writer,
                client_ip,
                query,
                query_data,
                TransferRefusal::not_auth(reason, identity.signer.take()),
            )
            .await
        }
        Err(DnsError::Refused(reason)) => {
            refuse_tcp_xfr(
                dns_cx,
                writer,
                client_ip,
                query,
                query_data,
                TransferRefusal::refused(reason, identity.signer.take()),
            )
            .await
        }
        Err(error) => {
            track_result(XfrResult::Failed);

            transfer::save_failed(
                cx,
                client_ip,
                &query.zone_name,
                TransferKind::from_qtype(query.qtype),
                transport,
                error.to_string(),
            )
            .await;

            if matches!(error, DnsError::PeerClosed) {
                return Err(error);
            }

            // End this transfer on error, retaining the connection (RFC 5936, Section 4.1.2).
            // Sign the error under the authenticated key (RFC 8945, Section 5.3.1).
            let ended = async {
                let response = query.build_signed_error_response(
                    OptRcode::SERVFAIL,
                    None,
                    identity.signer.as_mut(),
                )?;
                writer.write_message(&response).await
            }
            .await;

            if let Err(error) = ended {
                log::debug!(
                    "Failed to end the XFR session from {}: {}",
                    client_ip,
                    error
                );
            }

            Err(error)
        }
    }
}

/// Send a stream refusal, then record its final outcome and diagnostic reason.
async fn refuse_tcp_xfr(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_ip: IpAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
    refusal: TransferRefusal,
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();
    let transport = writer.transport();
    let mut outcome = match &refusal {
        TransferRefusal::Dns { rcode, .. } if *rcode == OptRcode::NOTAUTH => XfrResult::NotAuth,
        _ if refusal.is_failure() => XfrResult::Failed,
        _ => XfrResult::Refused,
    };
    let mut reason = refusal.to_string();
    let response = match refusal.into_response(query_data, &message::QueryMetadata::from(query)) {
        Err(DnsError::Tsig(error)) => {
            outcome = XfrResult::Failed;
            reason = error.to_string();
            query
                .build_signed_error_response(OptRcode::SERVFAIL, None, None)
                .map_err(DnsError::from)
        }
        response => response,
    };

    // RFC 5936, Section 4.1.2: send an RCODE instead of dropping the connection.
    let sent = match response {
        Ok(response) => writer.write_message(&response).await,
        Err(error) => Err(error),
    };

    if let Err(error) = &sent {
        outcome = XfrResult::Failed;
        reason = error.to_string();
    }

    cx.metrics().track_xfr(query.qtype, transport, outcome);
    log::warn!(
        "Refused XFR {} query from {}: {}",
        transport,
        client_ip,
        reason
    );

    if outcome == XfrResult::Failed {
        transfer::save_failed(
            cx,
            client_ip,
            &query.zone_name,
            TransferKind::from_qtype(query.qtype),
            transport,
            reason,
        )
        .await;
    } else if outcome == XfrResult::Refused {
        transfer::save_refused(
            cx,
            client_ip,
            &query.zone_name,
            TransferKind::from_qtype(query.qtype),
            transport,
            reason,
        )
        .await;
    }

    sent
}

/// Answer a caller-checked UDP AXFR with TC; defer zone grants to the TCP retry.
/// Sign even truncated replies under the request's key (RFC 8945, Section 5.3).
pub(crate) async fn handle_udp_xfr(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    target: ReplyTarget,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();
    let client_addr = target.client_addr;

    let identity =
        authenticate_transfer(dns_cx, query_data, client_addr.ip(), TransferTransport::Udp)
            .await
            .and_then(|identity| authorize_transport(dns_cx, TransferTransport::Udp, identity));
    let (response, outcome) = match identity {
        Ok(mut identity) => (
            query
                .build_signed_truncated_response(identity.signer.as_mut())
                .map_err(DnsError::from),
            XfrResult::Truncated,
        ),
        Err(refusal) => {
            let mut failed = refusal.is_failure();
            log::warn!(
                "Refused XFR UDP query from {}: {}",
                client_addr.ip(),
                refusal
            );
            let response =
                match refusal.into_response(query_data, &message::QueryMetadata::from(query)) {
                    Err(DnsError::Tsig(error)) => {
                        failed = true;
                        log::warn!("Failed to encode XFR UDP TSIG refusal: {}", error);
                        query
                            .build_signed_error_response(OptRcode::SERVFAIL, None, None)
                            .map_err(DnsError::from)
                    }
                    response => response,
                };

            (
                response,
                if failed {
                    XfrResult::Failed
                } else {
                    XfrResult::Refused
                },
            )
        }
    };

    let sent = match response {
        Ok(response) => socket
            .send_to(&response, target, query.response_limit())
            .await
            .map(|_| ()),
        Err(error) => Err(error),
    };

    // The transfer itself follows over TCP; count this response only after sending it.
    cx.metrics().track_xfr(
        query.qtype,
        TransferTransport::Udp,
        if sent.is_err() {
            XfrResult::Failed
        } else {
            outcome
        },
    );

    sent
}
