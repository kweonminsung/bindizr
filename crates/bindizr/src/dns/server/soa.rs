//! Serves SOA queries over TCP and UDP, used by secondaries to poll the
//! primary's serial.

use std::net::{IpAddr, SocketAddr};

use bindizr_core::{
    config,
    dns::{
        message,
        message::{Rcode, Rtype},
        tsig::{RequestSignature, TransferSigner, request_signature},
    },
    log_info, log_warn,
    metrics::{SoaResult, track_soa},
};
use bindizr_service::zone::ZoneService;
use tokio::net::{TcpStream, UdpSocket};

use crate::dns::{
    error::XfrError,
    server::{
        auth::{TransferRefusal, authorize_transfer, signed_error},
        catalog,
    },
    wire,
};

/// Answer an SOA query over TCP.
pub(crate) async fn handle_tcp_soa(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let response = build_soa_response(query, client_addr.ip(), query_data)
        .await
        .inspect_err(|_| track_soa(SoaResult::Error))?;
    wire::write_tcp_message(stream, &response).await?;
    Ok(())
}

/// Build the response to an SOA query received over UDP.
pub(crate) async fn handle_udp_soa(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let response = build_soa_response(query, client_addr.ip(), query_data)
        .await
        .inspect_err(|_| track_soa(SoaResult::Error))?;
    socket.send_to(&response, client_addr).await?;
    Ok(())
}

/// `bindizr doctor` probes over the wire, reaching a concrete `listen_addr` from it.
fn is_self_probe(client_ip: IpAddr) -> bool {
    // A v4 client on a `::` listener arrives mapped, so canonicalize first.
    let client_ip = client_ip.to_canonical();
    client_ip.is_loopback() || client_ip == config::bindizr_config().dns.listen_addr.to_canonical()
}

/// The response bytes, which TCP and UDP send alike. A secondary polls the
/// serial with the key it transfers under, so one gate answers both.
async fn build_soa_response(
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    query_data: &[u8],
) -> Result<Vec<u8>, XfrError> {
    let zone_name_str = query.zone_name.as_str();

    let signer = match authorize_soa(query, client_ip, query_data).await {
        Ok(signer) => signer,
        Err(refusal) => {
            log_warn!(
                "Refused SOA query for {:?} from {}: {}",
                zone_name_str,
                client_ip,
                refusal.reason
            );
            track_soa(SoaResult::Refused);
            return refusal.into_response(query);
        }
    };

    log_info!("SOA query for zone {:?} from {}", zone_name_str, client_ip);

    let mut signer = signer;
    let build = |signer: Option<TransferSigner>| {
        let builder = message::DnsMessageBuilder::new(query.query_id, &query.qname, Rtype::SOA);
        match signer {
            Some(signer) => builder.sign_with(signer),
            None => builder,
        }
    };

    if catalog::is_catalog_zone(zone_name_str) {
        log_info!("SOA query for catalog zone: {}", catalog::CATALOG_ZONE_NAME);
        let (catalog_zone, _) = catalog::generate_catalog_zone().await?;
        let mut builder = build(signer);
        builder.add_catalog_soa(
            &catalog_zone,
            bindizr_core::dns::serial_to_u32(catalog_zone.serial)?,
        )?;
        track_soa(SoaResult::Ok);
        return Ok(builder.build()?);
    }

    let Some(zone) = ZoneService::find_by_name(zone_name_str).await? else {
        track_soa(SoaResult::NotAuth);
        return signed_error(query, Rcode::NOTAUTH, signer.as_mut());
    };

    log_info!(
        "SOA response: zone {} serial={}",
        zone_name_str,
        zone.serial
    );

    let mut builder = build(signer);
    builder.add_soa(&zone, bindizr_core::dns::serial_to_u32(zone.serial)?)?;

    track_soa(SoaResult::Ok);
    Ok(builder.build()?)
}

/// `bindizr doctor`'s own probe carries no key and is not a secondary, so it
/// passes ahead of both gates.
async fn authorize_soa(
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    query_data: &[u8],
) -> Result<Option<TransferSigner>, TransferRefusal> {
    // Only an unsigned probe skips the gate: a request that reached for a key
    // is held to it wherever it came from, or a wrong secret would pass.
    if is_self_probe(client_ip) && matches!(request_signature(query_data), RequestSignature::Absent)
    {
        return Ok(None);
    }
    authorize_transfer(query_data, client_ip, &query.zone_name).await
}
