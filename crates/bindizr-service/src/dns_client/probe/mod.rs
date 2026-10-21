//! SOA network probes for explicitly supplied targets.
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bindizr_core::dns::{
    Serial,
    address::AddressTarget,
    dnssec::EncodeWireNameError,
    message::{Name, Opcode, Rtype},
    name::ZoneName,
    query::{build_question, extract_soa_serial},
};
use thiserror::Error;

use super::{ExchangeMessageError, ResolveAddressError};

/// Why a server's SOA serial could not be read.
#[derive(Debug, Error)]
pub enum ProbeSoaError {
    #[error("invalid zone name: {0}")]
    ZoneName(#[from] EncodeWireNameError),
    #[error("failed to resolve: {0}")]
    Resolve(#[source] ResolveAddressError),
    #[error(transparent)]
    Exchange(#[from] ExchangeMessageError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ParseResponseError),
}

/// An SOA result and the resolved IPs used to look up transfer history.
#[derive(Debug)]
pub(crate) struct SoaProbe {
    pub(crate) address: String,
    pub(crate) serial: Result<Serial, ProbeSoaError>,
    pub(crate) clients: Vec<IpAddr>,
}

/// Resolve a target and try its addresses in order until one answers.
pub(crate) async fn probe_addresses(
    zone_name: &ZoneName,
    target: &AddressTarget,
    timeout: Duration,
) -> Result<SoaProbe, ProbeSoaError> {
    let qname = zone_name.to_wire_name()?;

    let addrs = match super::resolve_address_entry(target, timeout).await {
        Ok(addrs) => addrs,
        Err(error) => {
            return Ok(SoaProbe {
                address: target.to_string(),
                serial: Err(ProbeSoaError::Resolve(error)),
                clients: Vec::new(),
            });
        }
    };
    let clients = addrs.iter().map(SocketAddr::ip).collect();
    let mut probe = SoaProbe {
        address: target.to_string(),
        serial: Err(ProbeSoaError::Resolve(ResolveAddressError::NoAddresses)),
        clients,
    };

    for addr in addrs {
        probe.address = addr.to_string();
        probe.serial = probe_address(&qname, addr, timeout).await;
        if probe.serial.is_ok() {
            break;
        }
    }

    Ok(probe)
}

/// Query one explicit server for the zone's SOA serial (e.g. bindizr's own
/// listener during health checks).
pub async fn probe_server(
    server_addr: SocketAddr,
    zone_name: &ZoneName,
    timeout: Duration,
) -> Result<Serial, ProbeSoaError> {
    let qname = zone_name.to_wire_name()?;
    probe_address(&qname, server_addr, timeout).await
}

/// Query one address for the zone's authoritative SOA serial.
async fn probe_address(
    qname: &Name<Vec<u8>>,
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<Serial, ProbeSoaError> {
    let (query_id, builder) = build_question(Opcode::QUERY, false, false, qname, Rtype::SOA, None);
    let query = builder.finish();

    let response =
        super::exchange_with_tcp_fallback(server_addr, timeout, &query, "SOA probe").await?;

    Ok(Serial::from(extract_soa_serial(
        query_id, qname, &response,
    )?))
}

#[cfg(test)]
mod tests;
