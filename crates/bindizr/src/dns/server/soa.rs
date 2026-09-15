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
use bindizr_service::zone::{TransferAccess, ZoneService};
use tokio::net::{TcpStream, UdpSocket};

use crate::dns::{
    error::XfrError,
    server::{
        auth::{TransferIdentity, TransferRefusal, authenticate_transfer, signed_error},
        catalog,
    },
    wire,
};

/// Answer an SOA query over TCP. The outcome is counted once the answer is
/// on the wire: the metric says whether secondaries are getting a serial.
pub(crate) async fn handle_tcp_soa(
    stream: &mut TcpStream,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let (response, outcome) = build_soa_response(query, client_addr.ip(), query_data)
        .await
        .inspect_err(|_| track_soa(SoaResult::Error))?;
    wire::write_tcp_message(stream, &response)
        .await
        .inspect_err(|_| track_soa(SoaResult::Error))?;
    track_soa(outcome);
    Ok(())
}

/// Answer an SOA query over UDP, counted as the TCP one is.
pub(crate) async fn handle_udp_soa(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    query: &message::ParsedQuery,
    query_data: &[u8],
) -> Result<(), XfrError> {
    let (response, outcome) = build_soa_response(query, client_addr.ip(), query_data)
        .await
        .inspect_err(|_| track_soa(SoaResult::Error))?;
    socket
        .send_to(&response, client_addr)
        .await
        .inspect_err(|_| track_soa(SoaResult::Error))?;
    track_soa(outcome);
    Ok(())
}

/// `bindizr doctor` probes over the wire, reaching a concrete `listen_addr` from it.
fn is_self_probe(client_ip: IpAddr) -> bool {
    // A v4 client on a `::` listener arrives mapped, so canonicalize first.
    let client_ip = client_ip.to_canonical();
    client_ip.is_loopback() || client_ip == config::bindizr_config().dns.listen_addr.to_canonical()
}

/// The response bytes, which TCP and UDP send alike, and the outcome they
/// carry. A secondary polls the serial with the key it transfers under, so
/// one gate answers both, and the zone answered is the one that key is
/// granted.
async fn build_soa_response(
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    query_data: &[u8],
) -> Result<(Vec<u8>, SoaResult), XfrError> {
    let zone_name_str = query.zone_name.as_str();

    let mut identity = match authenticate_soa(query, client_ip, query_data).await {
        Ok(identity) => identity,
        Err(refusal) => {
            log_warn!(
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

    log_info!("SOA query for zone {:?} from {}", zone_name_str, client_ip);

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
        let mut builder = build(identity.signer);
        builder.add_catalog_soa(
            &catalog_zone,
            bindizr_core::dns::serial_to_u32(catalog_zone.serial)?,
        )?;
        return Ok((builder.build()?, SoaResult::Ok));
    }

    let zone = match ZoneService::authorize_transfer_by_name(zone_name_str, identity.key.as_ref())
        .await?
    {
        TransferAccess::Granted(zone) => zone,
        TransferAccess::NotZone => {
            return signed_error(query, Rcode::NOTAUTH, identity.signer.as_mut())
                .map(|response| (response, SoaResult::NotAuth));
        }
        TransferAccess::Refused(reason) => {
            log_warn!(
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

    log_info!(
        "SOA response: zone {} serial={}",
        zone_name_str,
        zone.serial
    );

    let mut builder = build(identity.signer);
    builder.add_soa(&zone, bindizr_core::dns::serial_to_u32(zone.serial)?)?;

    Ok((builder.build()?, SoaResult::Ok))
}

/// `bindizr doctor`'s own probe carries no key and is not a secondary, so it
/// passes ahead of both gates.
async fn authenticate_soa(
    query: &message::ParsedQuery,
    client_ip: IpAddr,
    query_data: &[u8],
) -> Result<TransferIdentity, TransferRefusal> {
    // Only an unsigned probe skips the gate: a request that reached for a key
    // is held to it wherever it came from, or a wrong secret would pass.
    if is_self_probe(client_ip) && matches!(request_signature(query_data), RequestSignature::Absent)
    {
        return Ok(TransferIdentity {
            key: None,
            signer: None,
        });
    }
    authenticate_transfer(query_data, client_ip, &query.zone_name).await
}
