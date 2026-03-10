use super::error::XfrError;
use crate::database::model::{record::Record, zone::Zone};
use domain::base::{Message, Name, ToName, iana::Rtype};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const DNS_TCP_MAX_SIZE: usize = 65535;

pub struct DnsMessageBuilder {
    query_id: u16,
    qname: Vec<u8>,
    qtype: u16,
    answers: Vec<Vec<u8>>,
}

impl DnsMessageBuilder {
    pub fn new(query_id: u16, qname: &Name<Vec<u8>>, qtype: Rtype) -> Self {
        Self {
            query_id,
            qname: qname.as_slice().to_vec(),
            qtype: qtype.to_int(),
            answers: Vec::new(),
        }
    }

    /// Add SOA record
    pub fn add_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), XfrError> {
        let mut rdata = Vec::new();

        // MNAME
        encode_domain_name(&zone.primary_ns, &mut rdata)?;

        // RNAME
        let rname = zone.admin_email.replace('@', ".");
        encode_domain_name(&rname, &mut rdata)?;

        // SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&(zone.refresh as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.retry as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.expire as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.minimum_ttl as u32).to_be_bytes());

        self.add_answer_raw(&zone.name, 6, zone.ttl as u32, &rdata)?;
        Ok(())
    }

    /// Add A record
    pub fn add_a_record(&mut self, name: &str, ttl: u32, addr: Ipv4Addr) -> Result<(), XfrError> {
        let rdata = addr.octets().to_vec();
        self.add_answer_raw(name, 1, ttl, &rdata)?;
        Ok(())
    }

    /// Add AAAA record
    pub fn add_aaaa_record(
        &mut self,
        name: &str,
        ttl: u32,
        addr: Ipv6Addr,
    ) -> Result<(), XfrError> {
        let rdata = addr.octets().to_vec();
        self.add_answer_raw(name, 28, ttl, &rdata)?;
        Ok(())
    }

    /// Add CNAME record
    pub fn add_cname_record(&mut self, name: &str, ttl: u32, target: &str) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 5, ttl, &rdata)?;
        Ok(())
    }

    /// Add MX record
    pub fn add_mx_record(
        &mut self,
        name: &str,
        ttl: u32,
        priority: u16,
        target: &str,
    ) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 15, ttl, &rdata)?;
        Ok(())
    }

    /// Add NS record
    pub fn add_ns_record(&mut self, name: &str, ttl: u32, target: &str) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 2, ttl, &rdata)?;
        Ok(())
    }

    /// Add TXT record
    pub fn add_txt_record(&mut self, name: &str, ttl: u32, text: &str) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        let text_bytes = text.as_bytes();

        // TXT records are stored as length-prefixed strings
        let mut offset = 0;
        while offset < text_bytes.len() {
            let chunk_len = (text_bytes.len() - offset).min(255);
            rdata.push(chunk_len as u8);
            rdata.extend_from_slice(&text_bytes[offset..offset + chunk_len]);
            offset += chunk_len;
        }

        self.add_answer_raw(name, 16, ttl, &rdata)?;
        Ok(())
    }

    /// Add PTR record
    pub fn add_ptr_record(&mut self, name: &str, ttl: u32, target: &str) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 12, ttl, &rdata)?;
        Ok(())
    }

    /// Add NS record for catalog zone. NS should be "invalid."
    pub fn add_catalog_ns(&mut self, zone: &Zone) -> Result<(), XfrError> {
        let owner_name = ensure_fqdn(&zone.name);
        self.add_ns_record(&owner_name, zone.ttl as u32, "invalid")?;
        Ok(())
    }

    /// Add version record for catalog zone
    pub fn add_catalog_version(&mut self, zone: &Zone) -> Result<(), XfrError> {
        let version_name = format!("version.{}.", zone.name.trim_end_matches('.'));
        self.add_txt_record(&version_name, zone.ttl as u32, "2")?;
        Ok(())
    }

    /// Add PTR record for catalog zone member
    pub fn add_catalog_ptr(&mut self, zone: &Zone, member_zone: &str) -> Result<(), XfrError> {
        let member_id = super::catalog::zone_name_to_member_id(member_zone);
        let ptr_name = format!("{}.zones.{}.", member_id, zone.name.trim_end_matches('.'));
        let ptr_target = ensure_fqdn(member_zone);
        self.add_ptr_record(&ptr_name, zone.ttl as u32, &ptr_target)?;
        Ok(())
    }

    /// Add primaries record for catalog zone member (specifies which primary server the member zone should use)
    /// Add RFC 9432 primaries record for catalog zone member
    pub fn add_catalog_primaries(
        &mut self,
        zone: &Zone,
        member_zone: &str,
        primary_ip: &str,
    ) -> Result<(), XfrError> {
        let member_id = super::catalog::zone_name_to_member_id(member_zone);
        let primaries_name = format!(
            "1.primaries.{}.zones.{}.",
            member_id,
            zone.name.trim_end_matches('.')
        );

        if let Ok(addr) = primary_ip.parse::<std::net::Ipv4Addr>() {
            self.add_a_record(&primaries_name, zone.ttl as u32, addr)?;
        } else if let Ok(addr) = primary_ip.parse::<std::net::Ipv6Addr>() {
            self.add_aaaa_record(&primaries_name, zone.ttl as u32, addr)?;
        }

        Ok(())
    }

    /// Add a record from database Record model
    pub fn add_record(&mut self, record: &Record, zone_name: &str) -> Result<(), XfrError> {
        let ttl = record.ttl.unwrap_or(3600) as u32;
        let owner_name = normalize_name(&record.name, zone_name);

        match record.record_type.as_str() {
            "A" => {
                let addr: Ipv4Addr = record.value.parse().map_err(|_| {
                    XfrError::ProtocolError(format!("Invalid A record: {}", record.value))
                })?;
                self.add_a_record(&owner_name, ttl, addr)?;
            }
            "AAAA" => {
                let addr: Ipv6Addr = record.value.parse().map_err(|_| {
                    XfrError::ProtocolError(format!("Invalid AAAA record: {}", record.value))
                })?;
                self.add_aaaa_record(&owner_name, ttl, addr)?;
            }
            "CNAME" => {
                self.add_cname_record(&owner_name, ttl, &record.value)?;
            }
            "MX" => {
                let priority = record.priority.unwrap_or(10) as u16;
                self.add_mx_record(&owner_name, ttl, priority, &record.value)?;
            }
            "NS" => {
                self.add_ns_record(&owner_name, ttl, &record.value)?;
            }
            "TXT" => {
                self.add_txt_record(&owner_name, ttl, &record.value)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Add raw answer record
    fn add_answer_raw(
        &mut self,
        name: &str,
        rtype: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Result<(), XfrError> {
        let mut answer = Vec::new();

        // NAME
        encode_domain_name(name, &mut answer)?;

        // TYPE
        answer.extend_from_slice(&rtype.to_be_bytes());

        // CLASS (IN = 1)
        answer.extend_from_slice(&1u16.to_be_bytes());

        // TTL
        answer.extend_from_slice(&ttl.to_be_bytes());

        // RDLENGTH
        answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());

        // RDATA
        answer.extend_from_slice(rdata);

        self.answers.push(answer);
        Ok(())
    }

    /// Build final DNS message
    pub fn build(self) -> Vec<u8> {
        let mut message = Vec::new();

        // Header (12 bytes)
        message.extend_from_slice(&self.query_id.to_be_bytes()); // ID
        message.push(0x84); // QR=1, Opcode=0, AA=1, TC=0, RD=0
        message.push(0x00); // RA=0, Z=0, RCODE=0 (NOERROR)
        message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        message.extend_from_slice(&(self.answers.len() as u16).to_be_bytes()); // ANCOUNT
        message.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        message.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

        // Question section
        message.extend_from_slice(&self.qname);
        message.extend_from_slice(&self.qtype.to_be_bytes()); // QTYPE
        message.extend_from_slice(&1u16.to_be_bytes()); // QCLASS (IN)

        // Answer section
        for answer in &self.answers {
            message.extend_from_slice(answer);
        }

        message
    }
}

fn ensure_fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

fn normalize_name(name: &str, zone: &str) -> String {
    if name.ends_with('.') {
        return name.to_string();
    }

    let zone_trimmed = zone.trim_end_matches('.');
    if name == "@" {
        return format!("{}.", zone_trimmed);
    }

    let owner_trimmed = name.trim_end_matches('.');
    let zone_suffix = format!(".{}", zone_trimmed.to_ascii_lowercase());
    let owner_lower = owner_trimmed.to_ascii_lowercase();

    if owner_lower == zone_trimmed.to_ascii_lowercase() || owner_lower.ends_with(&zone_suffix) {
        return format!("{}.", owner_trimmed);
    }

    format!("{}.{}.", owner_trimmed, zone_trimmed)
}

pub fn encode_domain_name(name: &str, buf: &mut Vec<u8>) -> Result<(), XfrError> {
    let name = name.trim_end_matches('.');

    if name.is_empty() {
        buf.push(0);
        return Ok(());
    }

    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(XfrError::ProtocolError(format!(
                "Label too long: {}",
                label
            )));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(())
}

type ParseQueryResult = (Name<Vec<u8>>, Rtype, Option<u32>, u16);

/// Parse a DNS query message from bytes
pub fn parse_query(data: &[u8]) -> Result<ParseQueryResult, XfrError> {
    let message = Message::from_octets(data)
        .map_err(|e| XfrError::ProtocolError(format!("Failed to parse DNS message: {}", e)))?;

    let query_id = message.header().id();

    // Extract the first question
    let question = message
        .first_question()
        .ok_or_else(|| XfrError::ProtocolError("No question in DNS query".to_string()))?;

    let qname = question.qname().to_name::<Vec<u8>>();
    let qtype = question.qtype();

    // For IXFR, try to extract SOA from authority section (client serial)
    let client_serial = if qtype == Rtype::IXFR {
        extract_ixfr_serial_from_query(data)
    } else {
        None
    };

    Ok((qname, qtype, client_serial, query_id))
}

fn extract_ixfr_serial_from_query(data: &[u8]) -> Option<u32> {
    if data.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;

    let mut pos = 12usize;

    // Skip questions
    for _ in 0..qdcount {
        let qname_len = skip_name(data, pos)?;
        pos = pos.checked_add(qname_len + 4)?;
        if pos > data.len() {
            return None;
        }
    }

    // Skip answers
    for _ in 0..ancount {
        pos = skip_rr(data, pos)?;
    }

    // Inspect authority records for SOA
    for _ in 0..nscount {
        let name_len = skip_name(data, pos)?;
        pos = pos.checked_add(name_len)?;
        if pos.checked_add(10)? > data.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start.checked_add(rdlen)?;
        if rdata_end > data.len() {
            return None;
        }

        // SOA
        if rtype == 6 {
            let mname_len = skip_name(data, rdata_start)?;
            let rname_pos = rdata_start.checked_add(mname_len)?;
            let rname_len = skip_name(data, rname_pos)?;
            let serial_pos = rname_pos.checked_add(rname_len)?;
            if serial_pos.checked_add(4)? <= rdata_end {
                return Some(u32::from_be_bytes([
                    data[serial_pos],
                    data[serial_pos + 1],
                    data[serial_pos + 2],
                    data[serial_pos + 3],
                ]));
            }
            return None;
        }

        pos = rdata_end;
    }

    None
}

fn skip_rr(data: &[u8], pos: usize) -> Option<usize> {
    let name_len = skip_name(data, pos)?;
    let header_pos = pos.checked_add(name_len)?;
    if header_pos.checked_add(10)? > data.len() {
        return None;
    }
    let rdlen = u16::from_be_bytes([data[header_pos + 8], data[header_pos + 9]]) as usize;
    let next = header_pos.checked_add(10 + rdlen)?;
    if next > data.len() {
        return None;
    }
    Some(next)
}

fn skip_name(data: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() {
        return None;
    }

    let mut pos = start;
    let mut consumed = 0usize;
    let mut guard = 0usize;

    loop {
        if pos >= data.len() || guard > data.len() {
            return None;
        }
        guard += 1;

        let len = data[pos];
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            consumed = consumed.checked_add(2)?;
            return Some(consumed);
        }

        if len == 0 {
            consumed = consumed.checked_add(1)?;
            return Some(consumed);
        }

        let label_len = len as usize;
        if label_len > 63 {
            return None;
        }

        if pos.checked_add(1 + label_len)? > data.len() {
            return None;
        }

        pos += 1 + label_len;
        consumed = consumed.checked_add(1 + label_len)?;
    }
}

pub fn encode_tcp_message(message: &[u8]) -> Vec<u8> {
    let len = message.len() as u16;
    let mut result = Vec::with_capacity(2 + message.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(message);
    result
}

pub async fn read_tcp_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, XfrError> {
    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(XfrError::IoError)?;

    let len = u16::from_be_bytes(len_buf) as usize;

    if len > DNS_TCP_MAX_SIZE {
        return Err(XfrError::ProtocolError(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut message_buf = vec![0u8; len];
    reader
        .read_exact(&mut message_buf)
        .await
        .map_err(XfrError::IoError)?;

    Ok(message_buf)
}

pub async fn write_tcp_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), XfrError> {
    let encoded = encode_tcp_message(message);
    writer
        .write_all(&encoded)
        .await
        .map_err(XfrError::IoError)?;
    writer.flush().await.map_err(XfrError::IoError)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_name;

    #[test]
    fn test_normalize_name_relative() {
        assert_eq!(normalize_name("sub", "example.com"), "sub.example.com.");
    }

    #[test]
    fn test_normalize_name_zone_qualified() {
        assert_eq!(
            normalize_name("www.example.com", "example.com."),
            "www.example.com."
        );
        assert_eq!(
            normalize_name("example.com", "example.com."),
            "example.com."
        );
    }

    #[test]
    fn test_normalize_name_fqdn_and_apex() {
        assert_eq!(normalize_name("sub.", "example.com."), "sub.");
        assert_eq!(normalize_name("@", "example.com."), "example.com.");
    }
}
