//! Serves SOA queries over TCP and UDP, used by secondaries to poll the
//! primary's serial, and a UDP IXFR, which the SOA alone answers.

use std::net::{IpAddr, SocketAddr};

use bindizr_core::{
    dns::{
        DNS_TCP_MAX_SIZE, message,
        message::{ExtendedErrorCode, OptRcode, Rtype},
        tsig::{RequestSignature, TransferSigner, request_signature},
    },
    metrics::{SoaResult, XfrResult},
    model::transfer::TransferTransport,
};
use bindizr_service::zone::{self, TransferAccess};
use tokio::net::UdpSocket;

use crate::dns::{
    error::XfrError,
    server::{
        DnsContext,
        auth::{TransferIdentity, TransferRefusal, authenticate_transfer, authorize_transport},
        catalog,
    },
    stream::ResponseWriter,
};

/// Answer an SOA query over TCP. The outcome is counted once the answer is
/// on the wire: the metric says whether secondaries are getting a serial.
pub(crate) async fn handle_tcp_soa(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let cx = dns_cx.daemon();
    let (response, outcome) = handle_soa_request(
        dns_cx,
        query,
        client_addr.ip(),
        query_data,
        writer.transport(),
        DNS_TCP_MAX_SIZE,
    )
    .await
    .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    writer
        .write_message(&response)
        .await
        .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    cx.metrics().track_soa(outcome);
    Ok(())
}

/// Answer an SOA query over UDP, counted as the TCP one is.
pub(crate) async fn handle_udp_soa(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let cx = dns_cx.daemon();
    let (response, outcome) = handle_soa_request(
        dns_cx,
        query,
        client_addr.ip(),
        query_data,
        TransferTransport::Udp,
        query.udp_payload_limit(),
    )
    .await
    .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    socket
        .send_to(&response, client_addr)
        .await
        .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    cx.metrics().track_soa(outcome);
    Ok(())
}

/// Answer an IXFR over UDP with the zone's SOA alone, counted as a
/// `truncated` transfer since the transfer itself follows over TCP.
pub(crate) async fn handle_udp_ixfr(
    dns_cx: &DnsContext,
    socket: &UdpSocket,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let cx = dns_cx.daemon();
    let (response, outcome) = handle_soa_request(
        dns_cx,
        query,
        client_addr.ip(),
        query_data,
        TransferTransport::Udp,
        query.udp_payload_limit(),
    )
    .await
    .inspect_err(|_| {
        cx.metrics()
            .track_xfr(Rtype::IXFR, TransferTransport::Udp, XfrResult::Failed)
    })?;
    socket
        .send_to(&response, client_addr)
        .await
        .inspect_err(|_| {
            cx.metrics()
                .track_xfr(Rtype::IXFR, TransferTransport::Udp, XfrResult::Failed)
        })?;
    let result = match outcome {
        SoaResult::Ok => XfrResult::Truncated,
        SoaResult::Refused => XfrResult::Refused,
        SoaResult::NotAuth => XfrResult::NotAuth,
        SoaResult::Failed => XfrResult::Failed,
    };
    cx.metrics()
        .track_xfr(Rtype::IXFR, TransferTransport::Udp, result);
    Ok(())
}

/// `bindizr doctor` probes over the wire, reaching a concrete `listen_addr` from it.
fn is_self_probe(dns_cx: &DnsContext, client_ip: IpAddr) -> bool {
    // A v4 client on a `::` listener arrives mapped, so canonicalize first.
    let client_ip = client_ip.to_canonical();
    client_ip.is_loopback() || client_ip == dns_cx.daemon().config().dns.listen_addr.to_canonical()
}

/// Build the SOA response and outcome for any transport, applying the same
/// gate as transfers because secondaries poll with their transfer key. An
/// answer over `max_len` goes out truncated, for UDP.
async fn handle_soa_request(
    dns_cx: &DnsContext,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    query_data: &[u8],
    transport: TransferTransport,
    max_len: usize,
) -> Result<(Vec<u8>, SoaResult), XfrError> {
    let cx = dns_cx.daemon();
    let zone_name_str = query.zone_name.as_str();

    // A UDP IXFR is a transfer; a SOA query is not.
    let identity = authenticate_soa(dns_cx, client_ip, query_data, transport)
        .await
        .and_then(|identity| {
            if query.qtype == Rtype::IXFR {
                authorize_transport(dns_cx, transport, identity)
            } else {
                Ok(identity)
            }
        });
    let mut identity = match identity {
        Ok(identity) => identity,
        Err(refusal) => {
            log::warn!(
                "Refused {} query for {:?} from {}: {}",
                query.qtype,
                zone_name_str,
                client_ip,
                refusal.reason
            );
            return refusal
                .into_response(query)
                .map(|response| (response, SoaResult::Refused));
        }
    };

    log::info!(
        "{} query for zone {:?} from {}",
        query.qtype,
        zone_name_str,
        client_ip
    );

    // The question is echoed as asked: SOA, or a UDP IXFR answered by it.
    let build = |signer: Option<TransferSigner>| {
        let builder = message::DnsMessageBuilder::new(query, query.qtype);
        match signer {
            Some(signer) => builder.sign_with(signer),
            None => builder,
        }
    };

    if cx.config().dns.is_catalog_zone(zone_name_str) {
        log::info!(
            "{} query for catalog zone: {}",
            query.qtype,
            cx.config().dns.catalog_zone_name
        );
        let zones = match zone::authorize_catalog_content(cx, identity.key.as_ref()).await? {
            TransferAccess::Granted(zones) => zones,
            TransferAccess::NotAuth => {
                return Ok(query.signed_error_response(
                    OptRcode::NOTAUTH,
                    Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                    identity.signer.as_mut(),
                )?)
                .map(|response| (response, SoaResult::NotAuth));
            }
            TransferAccess::Refused(reason) => {
                log::warn!(
                    "Refused {} query for {:?} from {}: {}",
                    query.qtype,
                    zone_name_str,
                    client_ip,
                    reason
                );
                return TransferRefusal::refused(reason, identity.signer)
                    .into_response(query)
                    .map(|response| (response, SoaResult::Refused));
            }
        };
        let (catalog_zone, _) = catalog::generate_catalog_zone(dns_cx, zones).await?;
        let mut builder = build(identity.signer);
        builder.add_catalog_soa(&catalog_zone, catalog_zone.serial)?;
        return Ok((builder.build(max_len)?, SoaResult::Ok));
    }

    // A name the zone type refuses is answered NOTAUTH like a missing zone.
    let access = match zone::normalize_name(zone_name_str) {
        Ok(zone_name) => {
            zone::authorize_transfer_by_name(cx, &zone_name, identity.key.as_ref()).await?
        }
        Err(_) => TransferAccess::NotAuth,
    };
    let zone = match access {
        TransferAccess::Granted(zone) => zone,
        TransferAccess::NotAuth => {
            return Ok(query.signed_error_response(
                OptRcode::NOTAUTH,
                Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                identity.signer.as_mut(),
            )?)
            .map(|response| (response, SoaResult::NotAuth));
        }
        TransferAccess::Refused(reason) => {
            log::warn!(
                "Refused {} query for {:?} from {}: {}",
                query.qtype,
                zone_name_str,
                client_ip,
                reason
            );
            return TransferRefusal::refused(reason, identity.signer)
                .into_response(query)
                .map(|response| (response, SoaResult::Refused));
        }
    };

    log::info!(
        "SOA response: zone {} serial={}",
        zone_name_str,
        zone.serial
    );

    let mut builder = build(identity.signer);
    builder.add_soa(&zone, zone.serial)?;

    Ok((builder.build(max_len)?, SoaResult::Ok))
}

/// `bindizr doctor`'s own probe carries no key and is not a secondary, so it
/// passes ahead of both gates.
async fn authenticate_soa(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
    query_data: &[u8],
    transport: TransferTransport,
) -> Result<TransferIdentity, TransferRefusal> {
    // Only an unsigned probe skips the gate: a request that reached for a key
    // is held to it wherever it came from, or a wrong secret would pass.
    if is_self_probe(dns_cx, client_ip)
        && matches!(request_signature(query_data), RequestSignature::Absent)
    {
        return Ok(TransferIdentity {
            key: None,
            signer: None,
        });
    }
    authenticate_transfer(dns_cx, query_data, client_ip, transport).await
}
