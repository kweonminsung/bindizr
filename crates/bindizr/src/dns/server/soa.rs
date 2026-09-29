//! Serves SOA queries over TCP and UDP, used by secondaries to poll the
//! primary's serial.

use std::net::{IpAddr, SocketAddr};

use bindizr_core::{
    dns::{
        message,
        message::{Rcode, Rtype},
        tsig::{RequestSignature, TransferSigner, request_signature},
    },
    metrics::SoaResult,
};
use bindizr_service::zone::{self, TransferAccess};
use tokio::net::{TcpStream, UdpSocket};

use crate::dns::{
    error::XfrError,
    server::{
        DnsContext,
        auth::{TransferIdentity, TransferRefusal, authenticate_transfer},
        catalog,
    },
    wire,
};

/// Answer an SOA query over TCP. The outcome is counted once the answer is
/// on the wire: the metric says whether secondaries are getting a serial.
pub(crate) async fn handle_tcp_soa(
    dns_cx: &DnsContext,
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let cx = dns_cx.daemon();
    let (response, outcome) = handle_soa_request(dns_cx, query, client_addr.ip(), query_data)
        .await
        .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    wire::write_tcp_message(stream, &response)
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
    let (response, outcome) = handle_soa_request(dns_cx, query, client_addr.ip(), query_data)
        .await
        .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    socket
        .send_to(&response, client_addr)
        .await
        .inspect_err(|_| cx.metrics().track_soa(SoaResult::Failed))?;
    cx.metrics().track_soa(outcome);
    Ok(())
}

/// `bindizr doctor` probes over the wire, reaching a concrete `listen_addr` from it.
fn is_self_probe(dns_cx: &DnsContext, client_ip: IpAddr) -> bool {
    // A v4 client on a `::` listener arrives mapped, so canonicalize first.
    let client_ip = client_ip.to_canonical();
    client_ip.is_loopback() || client_ip == dns_cx.daemon().config().dns.listen_addr.to_canonical()
}

/// The response bytes, which TCP and UDP send alike, and the outcome they
/// carry. A secondary polls the serial with the key it transfers under, so
/// one gate answers both, and the zone answered is the one that key is
/// granted.
async fn handle_soa_request(
    dns_cx: &DnsContext,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    query_data: &[u8],
) -> Result<(Vec<u8>, SoaResult), XfrError> {
    let cx = dns_cx.daemon();
    let zone_name_str = query.zone_name.as_str();

    let mut identity = match authenticate_soa(dns_cx, query, client_ip, query_data).await {
        Ok(identity) => identity,
        Err(refusal) => {
            log::warn!(
                "Refused SOA query for {:?} from {}: {}",
                zone_name_str,
                client_ip,
                refusal.reason
            );
            return refusal
                .into_response(query)
                .map(|response| (response, SoaResult::Refused));
        }
    };

    log::info!("SOA query for zone {:?} from {}", zone_name_str, client_ip);

    let build = |signer: Option<TransferSigner>| {
        let builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::SOA);
        match signer {
            Some(signer) => builder.sign_with(signer),
            None => builder,
        }
    };

    if cx.config().dns.is_catalog_zone(zone_name_str) {
        log::info!(
            "SOA query for catalog zone: {}",
            cx.config().dns.catalog_zone_name
        );
        let (catalog_zone, _) = catalog::generate_catalog_zone(dns_cx).await?;
        let mut builder = build(identity.signer);
        builder.add_catalog_soa(&catalog_zone, catalog_zone.serial)?;
        return Ok((builder.build()?, SoaResult::Ok));
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
            return Ok(query.signed_error_response(Rcode::NOTAUTH, identity.signer.as_mut())?)
                .map(|response| (response, SoaResult::NotAuth));
        }
        TransferAccess::Refused(reason) => {
            log::warn!(
                "Refused SOA query for {:?} from {}: {}",
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

    Ok((builder.build()?, SoaResult::Ok))
}

/// `bindizr doctor`'s own probe carries no key and is not a secondary, so it
/// passes ahead of both gates.
async fn authenticate_soa(
    dns_cx: &DnsContext,
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    query_data: &[u8],
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
    authenticate_transfer(dns_cx, query_data, client_ip, &query.zone_name).await
}
