//! Client-side AXFR: pull a whole zone from another server, the fetch half
//! of `zone import --from-server`.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::{
    dns::{
        message::{Name, Opcode, Rtype, encode_tcp_message},
        name::decode_name_labels,
        query::{TransferRr, build_question, extract_transfer_rrs},
    },
    model::record::RecordType,
};
use tokio::io::AsyncWriteExt;

/// Transfer the zone from `server` and render it as zone-file text ready
/// for the import parser.
pub(crate) async fn fetch_zone_file(server: &str, zone_name: &str) -> Result<String, String> {
    let rrs = transfer_zone(server, zone_name).await?;
    render_zone_file(&rrs)
}

/// Bounds on one inbound transfer, guarding against a runaway server.
const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSFER_RRS: usize = 200_000;
/// Whole-transfer deadline: resolution and every address attempt share it.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Transfer the zone from `server` (`host[:port]`, port 53 default) and
/// return its RRs, the delimiting SOAs included (RFC 5936, Section 2.2).
async fn transfer_zone(server: &str, zone_name: &str) -> Result<Vec<TransferRr>, String> {
    let qname =
        Name::<Vec<u8>>::from_str(zone_name).map_err(|e| format!("invalid zone name: {}", e))?;

    let deadline = tokio::time::Instant::now() + TRANSFER_TIMEOUT;
    let entries = tokio::time::timeout_at(
        deadline,
        super::resolve_address_entries(server, TRANSFER_TIMEOUT),
    )
    .await
    .map_err(|_| format!("{}: resolution timed out", server))?;
    let mut last = None;
    for (entry, result) in entries {
        let addrs = result.map_err(|e| format!("failed to resolve {}: {}", entry, e))?;
        for addr in addrs {
            match tokio::time::timeout_at(deadline, transfer_from(addr, &qname)).await {
                Ok(Ok(rrs)) => return Ok(rrs),
                Ok(Err(e)) => last = Some(format!("{}: {}", addr, e)),
                // The deadline is absolute; later attempts would time out too.
                Err(_) => return Err(format!("{}: transfer timed out", addr)),
            }
        }
    }
    Err(last.unwrap_or_else(|| "no server address to transfer from".to_string()))
}

/// One AXFR over TCP: read length-prefixed response messages until the
/// closing SOA repeats the opening one.
async fn transfer_from(addr: SocketAddr, qname: &Name<Vec<u8>>) -> Result<Vec<TransferRr>, String> {
    let (query_id, query) = build_question(Opcode::QUERY, false, false, qname, Rtype::AXFR);

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;
    stream
        .write_all(&encode_tcp_message(&query)?)
        .await
        .map_err(|e| format!("send failed: {}", e))?;

    let expected_owner = format!("{}.", qname);
    let expected_labels = owner_labels(&expected_owner)?;
    let mut rrs: Vec<TransferRr> = Vec::new();
    let mut total_bytes = 0usize;
    loop {
        let response = super::read_tcp_message(&mut stream)
            .await
            .map_err(|e| format!("read failed before the closing SOA: {}", e))?;
        total_bytes += response.len();
        if total_bytes > MAX_TRANSFER_BYTES {
            return Err(format!("transfer exceeds {} bytes", MAX_TRANSFER_BYTES));
        }

        let batch = extract_transfer_rrs(query_id, qname, rrs.is_empty(), &response)?;
        for rr in batch {
            if rrs.is_empty() {
                if rr.rtype != Rtype::SOA {
                    return Err("transfer does not start with the zone's SOA".to_string());
                }
                if owner_labels(&rr.name)? != expected_labels {
                    return Err(format!(
                        "transfer opens with the SOA of {}, not {}",
                        rr.name, expected_owner
                    ));
                }
            } else if rr.rtype == Rtype::SOA {
                // The stream ends by repeating the opening SOA (RFC 5936, Section 2.2).
                let opening = &rrs[0];
                if owner_labels(&rr.name)? != owner_labels(&opening.name)?
                    || rr.rdata != opening.rdata
                {
                    return Err("transfer carries a SOA that is not the opening one".to_string());
                }
                rrs.push(rr);
                return Ok(rrs);
            }
            rrs.push(rr);
            if rrs.len() > MAX_TRANSFER_RRS {
                return Err(format!("transfer exceeds {} records", MAX_TRANSFER_RRS));
            }
        }
    }
}

/// Owner names compare as labels, never as text (RFC 4343 case, escapes).
fn owner_labels(name: &str) -> Result<Vec<String>, String> {
    decode_name_labels(name)
        .map(|(labels, _)| labels)
        .map_err(|e| format!("invalid owner name '{}': {}", name, e))
}

/// Render transferred RRs as zone-file lines. SOA and DNSSEC-derived
/// rows are dropped (the zone keeps its own SOA fields and signs itself);
/// any other unsupported type fails the import rather than thinning the
/// zone silently.
fn render_zone_file(rrs: &[TransferRr]) -> Result<String, String> {
    let mut lines = String::new();
    for rr in rrs {
        if matches!(
            rr.rtype,
            Rtype::SOA
                | Rtype::RRSIG
                | Rtype::NSEC
                | Rtype::NSEC3
                | Rtype::NSEC3PARAM
                | Rtype::DNSKEY
                | Rtype::CDS
                | Rtype::CDNSKEY
        ) {
            continue;
        }
        RecordType::from_rtype(rr.rtype).map_err(|_| {
            format!(
                "the source zone carries a record type bindizr does not store: {} {}",
                rr.name, rr.rtype
            )
        })?;
        lines.push_str(&format!(
            "{} {} IN {} {}\n",
            rr.name, rr.ttl, rr.rtype, rr.rdata
        ));
    }
    Ok(lines)
}
