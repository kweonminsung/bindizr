//! Serves SOA queries over TCP and UDP, used by secondaries to poll the
//! primary's serial, and a UDP IXFR, which the SOA alone answers.

use std::net::{IpAddr, SocketAddr};

use bindizr_core::dns::message::{
    DnsMessageBuilder, ExtendedErrorCode, OptRcode, ParsedQuery, QueryMetadata, Rtype,
};
use bindizr_core::dns::tsig;
use bindizr_core::dns::tsig::{RequestSignature, TransferSigner};
use bindizr_core::metrics::{SoaResult, XfrResult};
use bindizr_core::model::transfer::TransferTransport;
use bindizr_service::authorization::Caller;
use bindizr_service::zone;
use bindizr_service::zone::TransferAccess;

use crate::dns::error::DnsError;
use crate::dns::server::auth::{TransferIdentity, TransferRefusal};
use crate::dns::server::{DnsContext, auth};
use crate::dns::stream::ResponseWriter;
use crate::dns::udp::{ReplyTarget, UdpSocket};

/// Answer an SOA query over TCP. The outcome is counted once the answer is
/// on the wire: the metric says whether secondaries are getting a serial.
pub(crate) async fn handle_tcp_soa(
    dns_cx: &DnsContext,
    writer: &ResponseWriter,
    client_addr: SocketAddr,
    query: &ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();

    let (response, outcome) = handle_soa_request(
        dns_cx,
        client_addr.ip(),
        query,
        query_data,
        writer.transport(),
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
    target: ReplyTarget,
    query: &ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();

    let (response, outcome) = handle_soa_request(
        dns_cx,
        target.client_addr.ip(),
        query,
        query_data,
        TransferTransport::Udp,
    )
    .await
    .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    socket
        .send_to(&response, target, query.response_limit())
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
    target: ReplyTarget,
    query: &ParsedQuery,
    query_data: &[u8],
) -> Result<(), DnsError> {
    let cx = dns_cx.daemon();

    let (response, outcome) = handle_soa_request(
        dns_cx,
        target.client_addr.ip(),
        query,
        query_data,
        TransferTransport::Udp,
    )
    .await
    .inspect_err(|_| {
        cx.metrics()
            .track_xfr(Rtype::IXFR, TransferTransport::Udp, XfrResult::Failed);
    })?;
    socket
        .send_to(&response, target, query.response_limit())
        .await
        .inspect_err(|_| {
            cx.metrics()
                .track_xfr(Rtype::IXFR, TransferTransport::Udp, XfrResult::Failed);
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

/// Return whether the client is `bindizr doctor` probing over the wire,
/// reaching a concrete `listen_addr` from it.
fn is_self_probe(dns_cx: &DnsContext, client_ip: IpAddr) -> bool {
    client_ip.is_loopback() || client_ip == dns_cx.daemon().config().dns.listen_addr.to_canonical()
}

/// Build an SOA response under the transfer gate for polling secondaries.
/// The query carries the response budget, including its transport.
async fn handle_soa_request(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
    query: &ParsedQuery,
    query_data: &[u8],
    transport: TransferTransport,
) -> Result<(Vec<u8>, SoaResult), DnsError> {
    let cx = dns_cx.daemon();
    let zone_name_str = query.zone_name.as_str();

    // A UDP IXFR is a transfer; a SOA query is not.
    let identity = if query.qtype == Rtype::IXFR {
        auth::authenticate_transfer(dns_cx, client_ip, query_data, transport)
            .await
            .and_then(|identity| auth::authorize_transport(dns_cx, transport, identity))
    } else {
        authenticate_soa(dns_cx, client_ip, query_data, transport).await
    };
    let mut identity = match identity {
        Ok(identity) => identity,
        Err(refusal) => {
            let outcome = if refusal.is_failure() {
                SoaResult::Failed
            } else {
                SoaResult::Refused
            };
            log::warn!(
                "Refused {} query for {zone_name_str:?} from {client_ip}: {refusal}",
                query.qtype
            );

            return match refusal.into_response(&QueryMetadata::from(query), query_data) {
                Ok(response) => Ok((response, outcome)),
                Err(DnsError::Tsig(error)) => {
                    log::warn!("Failed to encode {} TSIG refusal: {error}", query.qtype);
                    Ok((
                        query.build_signed_error_response(OptRcode::SERVFAIL, None, None)?,
                        SoaResult::Failed,
                    ))
                }
                Err(error) => Err(error),
            };
        }
    };

    log::info!(
        "{} query for zone {zone_name_str:?} from {client_ip}",
        query.qtype
    );

    // The question is echoed as asked: SOA, or a UDP IXFR answered by it.
    let build = |signer: Option<TransferSigner>| {
        let mut builder = DnsMessageBuilder::new(query, query.qtype);

        if let Some(signer) = signer {
            builder = builder.sign_with(signer);
        }

        builder
    };

    if cx.config().dns.is_catalog_zone(zone_name_str) {
        log::info!(
            "{} query for catalog zone: {}",
            query.qtype,
            cx.config().dns.catalog_zone_name
        );

        let access = match zone::refresh_catalog_content(cx, &identity.caller).await {
            Ok(access) => access,
            Err(error) => {
                log::warn!(
                    "Failed to load catalog content for {} query for {zone_name_str:?} from {client_ip}: {error}",
                    query.qtype
                );
                return Ok((
                    query.build_signed_error_response(
                        OptRcode::SERVFAIL,
                        None,
                        identity.signer.as_mut(),
                    )?,
                    SoaResult::Failed,
                ));
            }
        };
        let (catalog_zone, _) = match access {
            TransferAccess::Granted(content) => content,
            TransferAccess::NotAuth => {
                return Ok((
                    query.build_signed_error_response(
                        OptRcode::NOTAUTH,
                        Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                        identity.signer.as_mut(),
                    )?,
                    SoaResult::NotAuth,
                ));
            }
            TransferAccess::Refused(reason) => {
                log::warn!(
                    "Refused {} query for {zone_name_str:?} from {client_ip}: {reason}",
                    query.qtype
                );
                return TransferRefusal::refused(reason, identity.signer)
                    .into_response(&QueryMetadata::from(query), query_data)
                    .map(|response| (response, SoaResult::Refused));
            }
        };
        let mut builder = build(identity.signer);
        builder.add_catalog_soa(&catalog_zone)?;

        return Ok((builder.build()?, SoaResult::Ok));
    }

    // A name the zone type refuses is answered NOTAUTH like a missing zone.
    let include_signatures = query.qtype == Rtype::SOA && query.edns.dnssec_ok();

    let access = match zone::normalize_name(zone_name_str) {
        Ok(zone_name) => match zone::authorize_soa_content_by_name(
            cx,
            &identity.caller,
            &zone_name,
            include_signatures,
        )
        .await
        {
            Ok(access) => access,
            Err(error) => {
                log::warn!(
                    "Failed to load SOA content for {} query for {zone_name_str:?} from {client_ip}: {error}",
                    query.qtype
                );
                return Ok((
                    query.build_signed_error_response(
                        OptRcode::SERVFAIL,
                        None,
                        identity.signer.as_mut(),
                    )?,
                    SoaResult::Failed,
                ));
            }
        },
        Err(_) => TransferAccess::NotAuth,
    };
    let (zone, signatures) = match access {
        TransferAccess::Granted(content) => content,
        TransferAccess::NotAuth => {
            return Ok((
                query.build_signed_error_response(
                    OptRcode::NOTAUTH,
                    Some(ExtendedErrorCode::NOT_AUTHORITATIVE),
                    identity.signer.as_mut(),
                )?,
                SoaResult::NotAuth,
            ));
        }
        TransferAccess::Refused(reason) => {
            log::warn!(
                "Refused {} query for {zone_name_str:?} from {client_ip}: {reason}",
                query.qtype
            );
            return TransferRefusal::refused(reason, identity.signer)
                .into_response(&QueryMetadata::from(query), query_data)
                .map(|response| (response, SoaResult::Refused));
        }
    };

    log::info!("SOA response: zone {zone_name_str} serial={}", zone.serial);

    let mut builder = build(identity.signer);
    builder.add_soa(&zone, zone.serial)?;

    for signature in signatures {
        builder.add_raw_rdata(
            query.qname.clone(),
            signature.record_type.wire_type(),
            signature.ttl.as_secs(),
            signature.rdata,
        )?;
    }

    Ok((builder.build()?, SoaResult::Ok))
}

/// Authenticate an SOA query. `bindizr doctor`'s own probe carries no key and
/// is not a secondary, so it passes ahead of both gates.
async fn authenticate_soa(
    dns_cx: &DnsContext,
    client_ip: IpAddr,
    query_data: &[u8],
    transport: TransferTransport,
) -> Result<TransferIdentity, TransferRefusal> {
    // Only an unsigned probe skips the gate: a request that reached for a key
    // is held to it wherever it came from, or a wrong secret would pass.
    if is_self_probe(dns_cx, client_ip)
        && tsig::request_signature(query_data) == RequestSignature::Absent
    {
        return Ok(TransferIdentity {
            caller: Caller::unsigned_dns(),
            signer: None,
        });
    }

    auth::authenticate_transfer(dns_cx, client_ip, query_data, transport).await
}
