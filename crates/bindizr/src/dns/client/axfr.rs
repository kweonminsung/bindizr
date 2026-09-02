//! Client-side AXFR: pull a whole zone from another server, the fetch half
//! of `zone import --from-server`.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use async_trait::async_trait;
use bindizr_core::{
    dns::{
        message::{Name, Opcode, Rtype},
        query::{TransferRecord, build_question, extract_transfer_records},
    },
    model::record::RecordType,
};
use bindizr_service::transfer::ZoneTransferClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The service's transfer seam, backed by this module's AXFR client.
pub(crate) struct AxfrTransferClient;

#[async_trait]
impl ZoneTransferClient for AxfrTransferClient {
    async fn fetch_zone_file(&self, server: &str, zone_name: &str) -> Result<String, String> {
        let records = transfer_zone(server, zone_name).await?;
        render_zone_file(&records)
    }
}

/// Bounds on one inbound transfer, guarding against a runaway server.
const MAX_TRANSFER_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSFER_RECORDS: usize = 200_000;
/// Whole-transfer deadline: connect, query, and every response frame.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Transfer the zone from `server` (`host[:port]`, port 53 default) and
/// return its records, the delimiting SOAs included (RFC 5936, Section 2.2).
pub(crate) async fn transfer_zone(
    server: &str,
    zone_name: &str,
) -> Result<Vec<TransferRecord>, String> {
    let qname =
        Name::<Vec<u8>>::from_str(zone_name).map_err(|e| format!("invalid zone name: {}", e))?;

    let mut last = None;
    for (entry, result) in super::resolve_secondary_entries(server, TRANSFER_TIMEOUT).await {
        let addrs = result.map_err(|e| format!("failed to resolve {}: {}", entry, e))?;
        for addr in addrs {
            match tokio::time::timeout(TRANSFER_TIMEOUT, transfer_from(addr, &qname)).await {
                Ok(Ok(records)) => return Ok(records),
                Ok(Err(e)) => last = Some(format!("{}: {}", addr, e)),
                Err(_) => last = Some(format!("{}: transfer timed out", addr)),
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
    let frame = (query.len() as u16).to_be_bytes();
    stream
        .write_all(&frame)
        .await
        .map_err(|e| format!("send failed: {}", e))?;
    stream
        .write_all(&query)
        .await
        .map_err(|e| format!("send failed: {}", e))?;

    let expected_owner = format!("{}.", qname);
    let mut records: Vec<TransferRecord> = Vec::new();
    let mut total_bytes = 0usize;
    loop {
        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|e| format!("read failed before the closing SOA: {}", e))?;
        let length = usize::from(u16::from_be_bytes(length));

        total_bytes += length;
        if total_bytes > MAX_TRANSFER_BYTES {
            return Err(format!("transfer exceeds {} bytes", MAX_TRANSFER_BYTES));
        }
        let mut response = vec![0u8; length];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| format!("read failed before the closing SOA: {}", e))?;

        let batch = extract_transfer_records(query_id, &response)?;
        for record in batch {
            if records.is_empty() {
                if record.rtype != Rtype::SOA {
                    return Err("transfer does not start with the zone's SOA".to_string());
                }
                if !record.name.eq_ignore_ascii_case(&expected_owner) {
                    return Err(format!(
                        "transfer opens with the SOA of {}, not {}",
                        record.name, expected_owner
                    ));
                }
            } else if record.rtype == Rtype::SOA {
                // The stream ends by repeating the opening SOA (RFC 5936, Section 2.2).
                let opening = &records[0];
                if !record.name.eq_ignore_ascii_case(&opening.name) || record.rdata != opening.rdata
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

/// Render transferred records as zone-file lines. SOA and DNSSEC-derived
/// rows are dropped (the zone keeps its own SOA fields and signs itself);
/// any other unsupported type fails the import rather than thinning the
/// zone silently.
fn render_zone_file(records: &[TransferRecord]) -> Result<String, String> {
    let mut lines = String::new();
    for record in records {
        if matches!(
            record.rtype,
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
        RecordType::from_rtype(record.rtype).map_err(|_| {
            format!(
                "the source zone carries a record type bindizr does not store: {} {}",
                record.name, record.rtype
            )
        })?;
        lines.push_str(&format!(
            "{} {} IN {} {}\n",
            record.name, record.ttl, record.rtype, record.rdata
        ));
    }
    Ok(lines)
}
