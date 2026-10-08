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

use std::{net::SocketAddr, sync::Arc};

use auth::{TransferRefusal, authenticate_transfer, transport_refusal};
use bindizr_core::{
    dns::message::{ExtendedErrorCode, Rcode, Rtype},
    metrics::XfrResult,
    model::transfer::{TransferKind, TransferTransport},
};
use bindizr_service::{Context, transfer};

use crate::dns::{error::XfrError, stream::ResponseWriter};

/// The DNS front end's context: the daemon's, plus the caches only this
/// front end reads. A handler takes it first as `dns_cx` and binds the
/// daemon's from it as `cx`.
#[derive(Debug)]
pub(crate) struct DnsContext {
    daemon: Arc<Context>,
    pub(crate) transfer_cache: transfer_cache::TransferCache,
    pub(crate) acl: acl::ResolvedAddrs,
}

impl DnsContext {
    /// The front end's context over the daemon's, with empty caches.
    pub(crate) fn new(daemon: Arc<Context>) -> Self {
        DnsContext {
            daemon,
            transfer_cache: transfer_cache::TransferCache::new(),
            acl: acl::ResolvedAddrs::new(),
        }
    }

    /// The daemon's context.
    pub(crate) fn daemon(&self) -> &Context {
        &self.daemon
    }
}

/// Check whether a query type requests AXFR or IXFR.
pub(crate) fn is_xfr_query_type(qtype: Rtype) -> bool {
    matches!(qtype, Rtype::AXFR | Rtype::IXFR)
}

/// Authenticate and serve a TCP zone transfer, returning refusals as DNS responses.
///
/// Count by the requested type so an IXFR falling back to AXFR still counts as IXFR.
pub(crate) async fn handle_tcp_xfr(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let cx = dns_cx.daemon();
    let client_ip = client_addr.ip();
    let transport = writer.transport();
    let track_result = |result| cx.metrics().track_xfr(query.qtype, transport, result);

    // The transport, then the key or the address; the zone's grant is decided
    // beside its row inside the transfer.
    let identity = match transport_refusal(dns_cx, transport) {
        Some(refusal) => Err(refusal),
        None => authenticate_transfer(dns_cx, query_data, client_ip, transport).await,
    };
    let mut identity = match identity {
        Ok(identity) => identity,
        Err(refusal) => {
            track_result(XfrResult::Refused);
            log::warn!(
                "Refused XFR {} query from {}: {}",
                transport,
                client_ip,
                refusal.reason
            );
            // Saved against the client too, so `secondary transfers` can say why
            // a secondary got nothing.
            transfer::save_refused(
                cx,
                client_ip,
                &query.zone_name,
                TransferKind::from_qtype(query.qtype),
                transport,
                refusal.reason.clone(),
            )
            .await;
            // RFC 5936, Section 2.2.1: refuse with an RCODE, not a dropped
            // connection.
            let response = refusal.into_response(query)?;
            writer.write_message(&response).await?;
            return Ok(());
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
            return Err(XfrError::InvalidQuery(format!(
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
        Err(XfrError::NotAuth(_)) => {
            track_result(XfrResult::NotAuth);
            let response = query.signed_error_response(
                Rcode::NOTAUTH,
                Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                identity.signer.as_mut(),
            )?;
            writer.write_message(&response).await?;
            Ok(())
        }
        Err(XfrError::Refused(reason)) => {
            track_result(XfrResult::Refused);
            log::warn!(
                "Refused XFR {} query from {}: {}",
                transport,
                client_ip,
                reason
            );
            transfer::save_refused(
                cx,
                client_ip,
                &query.zone_name,
                TransferKind::from_qtype(query.qtype),
                transport,
                reason.clone(),
            )
            .await;
            let response =
                TransferRefusal::refused(reason, identity.signer.take()).into_response(query)?;
            writer.write_message(&response).await?;
            Ok(())
        }
        Err(err) => {
            track_result(XfrResult::Failed);
            transfer::save_failed(
                cx,
                client_ip,
                &query.zone_name,
                TransferKind::from_qtype(query.qtype),
                transport,
                err.to_string(),
            )
            .await;
            // RFC 5936, Section 2.2: an error message ends the session, as the
            // connection stays open for the other queries it carries.
            let response = query.error_response(Rcode::SERVFAIL, None);
            if let Err(e) = writer.write_message(&response).await {
                log::debug!("Failed to end the XFR session from {}: {}", client_ip, e);
            }
            Err(err)
        }
    }
}

/// Answer an AXFR received over UDP with TC set, so an allowed client asks
/// again over TCP; the caller checked the qtype. A signed question is
/// answered under its key here too (RFC 8945, Section 5.3), truncated or not;
/// the zone's grant is decided on the TCP retry, beside the row it serves.
pub(crate) async fn handle_udp_xfr(
    dns_cx: &DnsContext,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Vec<u8> {
    let cx = dns_cx.daemon();
    let identity = match transport_refusal(dns_cx, TransferTransport::Udp) {
        Some(refusal) => Err(refusal),
        None => {
            authenticate_transfer(dns_cx, query_data, client_addr.ip(), TransferTransport::Udp)
                .await
        }
    };
    let mut identity = match identity {
        Ok(identity) => identity,
        Err(refusal) => {
            cx.metrics()
                .track_xfr(query.qtype, TransferTransport::Udp, XfrResult::Refused);
            log::warn!(
                "Refused XFR UDP query from {}: {}",
                client_addr.ip(),
                refusal.reason
            );
            return refusal.into_response(query).unwrap_or_else(|_| {
                query.error_response(Rcode::REFUSED, Some(ExtendedErrorCode::PROHIBITED))
            });
        }
    };
    // The transfer itself counts when the client returns over TCP.
    cx.metrics()
        .track_xfr(query.qtype, TransferTransport::Udp, XfrResult::Truncated);
    query
        .signed_truncated_response(identity.signer.as_mut())
        .unwrap_or_else(|_| query.truncated_response())
}
