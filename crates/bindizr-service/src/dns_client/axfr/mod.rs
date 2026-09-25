//! Client-side AXFR: pull a whole zone from another server, the fetch half
//! of `zone import --from-server`.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::dns::{
    message::{Name, Opcode, Rtype, encode_tcp_message},
    name::{decode_name_labels, to_fqdn},
    query::{TransferRecord, build_question, extract_transfer_records},
};
use tokio::io::AsyncWriteExt;

/// Transfer the zone from `server` and render it as zone-file text ready
/// for the import parser.
pub(crate) async fn fetch_zone_file(server: &str, zone_name: &str) -> Result<String, String> {
    let records = transfer_zone(server, zone_name).await?;
    Ok(render_zone_file(&records))
}

/// Bounds on one inbound transfer, guarding against a runaway server.
const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSFER_RECORDS: usize = 200_000;
/// Whole-transfer deadline: resolution and every address attempt share it.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Transfer the zone from `server` (`host[:port]`, port 53 default) and
/// return its RRs, the delimiting SOAs included (RFC 5936, Section 2.2).
async fn transfer_zone(server: &str, zone_name: &str) -> Result<Vec<TransferRecord>, String> {
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
                Ok(Ok(records)) => return Ok(records),
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
async fn transfer_from(
    addr: SocketAddr,
    qname: &Name<Vec<u8>>,
) -> Result<Vec<TransferRecord>, String> {
    let (query_id, query) = build_question(Opcode::QUERY, false, false, qname, Rtype::AXFR);

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;
    stream
        .write_all(&encode_tcp_message(&query)?)
        .await
        .map_err(|e| format!("send failed: {}", e))?;

    let expected_owner = to_fqdn(&qname.to_string());
    let expected_labels = owner_labels(&expected_owner)?;
    let mut records: Vec<TransferRecord> = Vec::new();
    let mut total_bytes = 0usize;
    loop {
        let response = super::read_tcp_message(&mut stream)
            .await
            .map_err(|e| format!("read failed before the closing SOA: {}", e))?;
        total_bytes += response.len();
        if total_bytes > MAX_TRANSFER_BYTES {
            return Err(format!("transfer exceeds {} bytes", MAX_TRANSFER_BYTES));
        }

        let batch = extract_transfer_records(query_id, qname, records.is_empty(), &response)?;
        for record in batch {
            if records.is_empty() {
                if record.rtype != Rtype::SOA {
                    return Err("transfer does not start with the zone's SOA".to_string());
                }
                if owner_labels(&record.name)? != expected_labels {
                    return Err(format!(
                        "transfer opens with the SOA of {}, not {}",
                        record.name, expected_owner
                    ));
                }
            } else if record.rtype == Rtype::SOA {
                // The stream ends by repeating the opening SOA (RFC 5936, Section 2.2).
                let opening = &records[0];
                if owner_labels(&record.name)? != owner_labels(&opening.name)?
                    || record.rdata != opening.rdata
                {
                    return Err("transfer carries a SOA that is not the opening one".to_string());
                }
                records.push(record);
                return Ok(records);
            }
            records.push(record);
            if records.len() > MAX_TRANSFER_RECORDS {
                return Err(format!("transfer exceeds {} records", MAX_TRANSFER_RECORDS));
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

/// Render transferred RRs as zone-file lines: the zone's SOA once, no
/// DNSSEC-derived rows (bindizr signs with its own keys), and every other
/// type as it arrived, for the parser to accept or report.
fn render_zone_file(records: &[TransferRecord]) -> String {
    let mut lines = String::new();
    let mut soa_rendered = false;
    for record in records {
        if matches!(
            record.rtype,
            Rtype::RRSIG
                | Rtype::NSEC
                | Rtype::NSEC3
                | Rtype::NSEC3PARAM
                | Rtype::DNSKEY
                | Rtype::CDS
                | Rtype::CDNSKEY
        ) {
            continue;
        }
        // The opening delimiter is what `--create` builds the zone from; the
        // closing repeat would read as a zone carrying two.
        if record.rtype == Rtype::SOA {
            if soa_rendered {
                continue;
            }
            soa_rendered = true;
        }
        // A type bindizr does not store is rendered anyway: the parser
        // reports it, so `--skip-unsupported` can pass over it.
        lines.push_str(&format!(
            "{} {} IN {} {}\n",
            record.name, record.ttl, record.rtype, record.rdata
        ));
    }
    lines
}

#[cfg(test)]
mod tests;
