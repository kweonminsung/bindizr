//! Inbound DNS serving: AXFR/IXFR dispatch with TSIG or ACL gating, SOA
//! responses, streaming the service's catalog zone, and RFC 2136 nsupdate handling.

pub(crate) mod acl;
pub(crate) mod auth;
pub(crate) mod axfr;
pub(crate) mod catalog;
pub(crate) mod ixfr;
pub(crate) mod nsupdate;
pub(crate) mod soa;
pub(crate) mod transfer_cache;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bindizr_core::dns::message;
use bindizr_core::dns::message::{
    Class, ExtendedErrorCode, Keepalive, Opcode, OptRcode, ParsedQuery, QueryMetadata,
    ResponseLimit, Rtype,
};
use bindizr_core::metrics::XfrResult;
use bindizr_core::model::transfer::{TransferKind, TransferTransport};
use bindizr_service::transfer::TransferLogErrorCode;
use bindizr_service::{Context, transfer};

use crate::dns::error::DnsError;
use crate::dns::server::acl::AddressCache;
use crate::dns::server::auth::QueryRefusal;
pub(crate) use crate::dns::server::auth::refuse_query;
use crate::dns::server::transfer_cache::TransferCache;
use crate::dns::stream::ResponseWriter;
use crate::dns::udp::{ReplyTarget, UdpSocket};

/// DNS-specific caches and daemon context; handlers take `dns_cx` and derive `cx`.
#[derive(Debug)]
pub(crate) struct DnsContext {
    daemon: Arc<Context>,
    pub(crate) transfer_cache: Arc<TransferCache>,
    pub(crate) address_cache: AddressCache,
}

impl DnsContext {
    /// Build the front end's context over the daemon's, with empty caches.
    pub(crate) fn new(daemon: Arc<Context>) -> Self {
        Self {
            daemon,
            transfer_cache: Arc::new(TransferCache::new()),
            address_cache: AddressCache::new(),
        }
    }

    /// Return the daemon's context.
    pub(crate) fn daemon(&self) -> &Arc<Context> {
        &self.daemon
    }
}

/// Classify unsupported opcodes from the header, including opaque request bodies.
pub(crate) async fn refuse_unsupported_opcode(
    dns_cx: &DnsContext,
    query_data: &[u8],
    keepalive: Keepalive,
    transport: TransferTransport,
) -> Result<Option<(Vec<u8>, ResponseLimit)>, DnsError> {
    let Some(opcode) = message::extract_opcode(query_data) else {
        return Ok(None);
    };

    // RFC 9103, Section 7.8: the TLS listener serves transfers alone, so an
    // UPDATE is refused there instead of reaching nsupdate.
    if opcode == Opcode::QUERY || (opcode == Opcode::UPDATE && transport != TransferTransport::Tls)
    {
        return Ok(None);
    }

    let Ok(metadata) = QueryMetadata::parse(query_data, keepalive) else {
        return Ok(None);
    };
    let (rcode, ede) = if let Some(rcode) = metadata.format_error() {
        (rcode, None)
    } else if opcode == Opcode::UPDATE && !message::has_readable_sections(query_data) {
        // An UPDATE has DNS sections, unlike an opaque body: one whose framing
        // does not read gets the header-only FORMERR any unreadable message does.
        (OptRcode::FORMERR, None)
    } else if transport == TransferTransport::Tls {
        (OptRcode::REFUSED, Some(ExtendedErrorCode::NOT_SUPPORTED))
    } else {
        (OptRcode::NOTIMP, Some(ExtendedErrorCode::NOT_SUPPORTED))
    };

    let response = refuse_query(dns_cx, &metadata, query_data, rcode, ede).await?;

    Ok(Some((response, metadata.response_limit())))
}

/// How to answer a parsed DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryDispatch {
    Soa,
    Transfer(TransferKind),
    Refuse {
        rcode: OptRcode,
        ede: Option<ExtendedErrorCode>,
    },
}

/// Select a handler or the DNS refusal a parsed query requires.
pub(crate) fn classify_query(
    client_addr: SocketAddr,
    query: &ParsedQuery,
    transport: TransferTransport,
) -> QueryDispatch {
    if let Some(rcode) = query.format_error() {
        log::info!("Refusing DNS {transport} query format from {client_addr}: {rcode}");
        return QueryDispatch::Refuse { rcode, ede: None };
    }

    let dispatch = if query.qtype == Rtype::SOA {
        Some(QueryDispatch::Soa)
    } else {
        TransferKind::try_from(query.qtype)
            .ok()
            .map(QueryDispatch::Transfer)
    };

    // RFC 9103, Section 7.8: refuse non-XoT traffic regardless of its class.
    if transport == TransferTransport::Tls && dispatch.is_none() {
        log::info!(
            "Refusing unsupported TLS query from {client_addr} (opcode={:?}, qtype={:?})",
            query.opcode,
            query.qtype
        );
        return QueryDispatch::Refuse {
            rcode: OptRcode::REFUSED,
            ede: Some(ExtendedErrorCode::NOT_SUPPORTED),
        };
    }
    if query.qclass != Class::IN {
        // Only IN is served; the question, class included, is copied into the
        // response (RFC 5936, Section 2.2.2).
        log::info!(
            "Refusing DNS {transport} class {} from {client_addr}",
            query.qclass
        );
        return QueryDispatch::Refuse {
            rcode: OptRcode::NOTAUTH,
            ede: Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
        };
    }
    if let Some(dispatch) = dispatch {
        return dispatch;
    }

    log::info!(
        "Refusing out-of-scope DNS {transport} query from {client_addr} (qtype={:?})",
        query.qtype
    );
    QueryDispatch::Refuse {
        rcode: OptRcode::REFUSED,
        ede: Some(ExtendedErrorCode::NOT_SUPPORTED),
    }
}

/// Authenticate and serve a zone transfer over TCP or TLS, answering refusals.
/// Count by the requested type so an IXFR falling back to AXFR still counts as IXFR.
pub(crate) async fn handle_stream_xfr(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query: &ParsedQuery,
    query_data: &[u8],
    kind: TransferKind,
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();
    let client_ip = client_addr.ip();
    let transport = writer.transport();

    // Zone grants are checked with the zone row; check key/address and transport here.
    let identity = tokio::select! {
        biased;
        () = writer.failed() => return Err(DnsError::PeerClosed),

        result = auth::admit_transfer(dns_cx, client_ip, query_data, transport) => result,
    };

    let mut identity = match identity {
        Ok(identity) => identity,
        Err(refusal) => {
            return refuse_stream_xfr(dns_cx, writer, client_ip, query, query_data, kind, refusal)
                .await;
        }
    };

    log::info!(
        "XFR {transport} query: zone={:?}, qtype={:?}, from={client_ip}, signed={}",
        query.zone_name,
        query.qtype,
        identity.signer.is_some()
    );

    let result = match kind {
        TransferKind::Axfr => {
            axfr::handle_axfr(dns_cx, writer, client_ip, query, kind, &mut identity).await
        }
        TransferKind::Ixfr => {
            ixfr::handle_ixfr(dns_cx, writer, client_ip, query, &mut identity).await
        }
    };

    // A missing zone gets NOTAUTH and an ungranted one REFUSED, both under the
    // key that asked; other transfer failures propagate to the listener.
    match result {
        Ok(()) => {
            cx.metrics().track_xfr(kind, transport, XfrResult::Ok);
            Ok(())
        }
        Err(error @ DnsError::NotAuth { .. }) => {
            refuse_stream_xfr(
                dns_cx,
                writer,
                client_ip,
                query,
                query_data,
                kind,
                QueryRefusal::not_auth(error.to_string(), identity.signer.take()),
            )
            .await
        }
        Err(DnsError::Refused { reason }) => {
            refuse_stream_xfr(
                dns_cx,
                writer,
                client_ip,
                query,
                query_data,
                kind,
                QueryRefusal::refused(reason, identity.signer.take()),
            )
            .await
        }
        Err(error) => {
            if let DnsError::Service(service_error) = &error
                && service_error.code().is_internal()
            {
                log::error!(
                    "{} from {client_ip} failed with a server fault: {service_error:?}",
                    query.qtype
                );
            }

            cx.metrics().track_xfr(kind, transport, XfrResult::Failed);

            transfer::save_failed(
                cx,
                client_ip,
                &query.zone_name,
                kind,
                transport,
                error.to_log_code(),
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
                log::debug!("Failed to end the XFR session from {client_ip}: {error}");
            }

            Err(error)
        }
    }
}

/// Send a stream refusal, then save its final outcome and fixed error classification.
async fn refuse_stream_xfr(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_ip: IpAddr,
    query: &ParsedQuery,
    query_data: &[u8],
    kind: TransferKind,
    refusal: QueryRefusal,
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();
    let transport = writer.transport();
    let mut outcome = match &refusal {
        QueryRefusal::Dns { rcode, .. } if *rcode == OptRcode::NOTAUTH => XfrResult::NotAuth,
        _ if refusal.is_failure() => XfrResult::Failed,
        _ => XfrResult::Refused,
    };
    let mut error_code = refusal.to_log_code();
    let mut reason = refusal.to_string();
    let response = match refusal.into_response(&QueryMetadata::from(query), query_data) {
        Err(DnsError::TsigResponse(error)) => {
            outcome = XfrResult::Failed;
            error_code = TransferLogErrorCode::TsigResponseEncodingFailed;
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
        error_code = error.to_log_code();
        reason = error.to_string();
    }

    cx.metrics().track_xfr(kind, transport, outcome);
    log::warn!("Refused XFR {transport} query from {client_ip}: {reason}");

    match outcome {
        XfrResult::Failed => {
            transfer::save_failed(cx, client_ip, &query.zone_name, kind, transport, error_code)
                .await;
        }
        XfrResult::Refused => {
            transfer::save_refused(cx, client_ip, &query.zone_name, kind, transport, error_code)
                .await;
        }
        _ => {}
    }

    sent
}

/// Answer a caller-checked UDP AXFR with TC; defer zone grants to the TCP retry.
/// Sign even truncated replies under the request's key (RFC 8945, Section 5.3).
/// A UDP refusal is counted but not saved to the transfer log: a datagram's
/// source address can be forged, so saving it would let anyone fill the log.
pub(crate) async fn handle_udp_axfr(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    target: ReplyTarget,
    query: &ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();
    let client_addr = target.client_addr;

    let identity =
        auth::admit_transfer(dns_cx, client_addr.ip(), query_data, TransferTransport::Udp).await;
    let (response, outcome) = match identity {
        Ok(mut identity) => (
            query
                .build_signed_truncated_response(identity.signer.as_mut())
                .map_err(DnsError::from),
            XfrResult::Truncated,
        ),
        Err(refusal) => {
            let mut failed = refusal.is_failure();
            log::warn!("Refused XFR UDP query from {}: {refusal}", client_addr.ip());
            let response = match refusal.into_response(&QueryMetadata::from(query), query_data) {
                Err(DnsError::TsigResponse(error)) => {
                    failed = true;
                    log::warn!("Failed to encode XFR UDP TSIG refusal: {error}");
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
        TransferKind::Axfr,
        TransferTransport::Udp,
        if sent.is_err() {
            XfrResult::Failed
        } else {
            outcome
        },
    );

    sent
}

#[cfg(test)]
mod tests;
