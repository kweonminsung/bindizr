//! DNS wire-format encoding for zone-transfer responses: message framing and
//! record/SOA serialization.

use std::net::{Ipv4Addr, Ipv6Addr};

use bindizr_core::dns::name::{
    MAX_DNS_LABEL_LEN, email_to_soa_mailbox, presentation_labels, to_fqdn, to_owner_fqdn,
};
use domain::{
    base::{Message, Name, ToName, iana::Rtype},
    rdata::Soa,
};

use crate::{
    error::XfrError,
    model::{record::Record, zone::Zone},
    protocol::DNS_TCP_MAX_SIZE,
    txt,
};

pub(crate) struct DnsMessageBuilder {
    query_id: u16,
    qname: Vec<u8>,
    qtype: u16,
    answers: Vec<Vec<u8>>,
    /// Total byte length of `answers`, kept incrementally because
    /// `message_len` runs after every appended answer.
    answers_len: usize,
}

impl DnsMessageBuilder {
    pub(crate) fn new(query_id: u16, qname: &Name<Vec<u8>>, qtype: Rtype) -> Self {
        Self {
            query_id,
            qname: qname.as_slice().to_vec(),
            qtype: qtype.to_int(),
            answers: Vec::new(),
            answers_len: 0,
        }
    }

    pub(crate) fn add_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), XfrError> {
        let mut rdata = Vec::new();

        encode_domain_name(&zone.primary_ns, &mut rdata)?;

        // Admin email in DNS SOA mailbox format
        let admin_email = email_to_soa_mailbox(&zone.admin_email)
            .map_err(|e| XfrError::ProtocolError(e.to_string()))?;
        encode_domain_name(&admin_email, &mut rdata)?;

        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&(zone.refresh as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.retry as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.expire as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.minimum_ttl as u32).to_be_bytes());

        self.add_answer_raw(&zone.name, 6, zone.ttl as u32, &rdata)?;
        Ok(())
    }

    /// Adds a catalog-zone SOA. MNAME and RNAME are intentionally invalid.
    pub(crate) fn add_catalog_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), XfrError> {
        let mut rdata = Vec::new();

        encode_domain_name("invalid", &mut rdata)?;
        encode_domain_name("invalid", &mut rdata)?;

        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&(zone.refresh as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.retry as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.expire as u32).to_be_bytes());
        rdata.extend_from_slice(&(zone.minimum_ttl as u32).to_be_bytes());

        self.add_answer_raw(&zone.name, 6, zone.ttl as u32, &rdata)?;
        Ok(())
    }

    /// Adds an SOA from a serial-specific snapshot.
    pub(crate) fn add_soa_from_snapshot(
        &mut self,
        soa: &crate::server::delta::ZoneSnapshot,
    ) -> Result<(), XfrError> {
        let mut rdata = Vec::new();

        encode_domain_name(&soa.primary_ns, &mut rdata)?;
        encode_domain_name(&soa.admin_email, &mut rdata)?;

        let serial = crate::server::delta::serial_to_u32(soa.serial)?;
        rdata.extend_from_slice(&serial.to_be_bytes());
        rdata.extend_from_slice(&(soa.refresh as u32).to_be_bytes());
        rdata.extend_from_slice(&(soa.retry as u32).to_be_bytes());
        rdata.extend_from_slice(&(soa.expire as u32).to_be_bytes());
        rdata.extend_from_slice(&(soa.minimum_ttl as u32).to_be_bytes());

        // IXFR SOA owner should be the transfer QNAME.
        let mut answer = Vec::with_capacity(self.qname.len() + 10 + rdata.len());
        answer.extend_from_slice(&self.qname);
        answer.extend_from_slice(&6u16.to_be_bytes()); // TYPE (SOA)
        answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS (IN = 1)
        answer.extend_from_slice(&(soa.ttl as u32).to_be_bytes());
        answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        answer.extend_from_slice(&rdata);

        self.push_answer(answer);
        Ok(())
    }

    pub(crate) fn add_a_record(
        &mut self,
        name: &str,
        ttl: u32,
        addr: Ipv4Addr,
    ) -> Result<(), XfrError> {
        let rdata = addr.octets().to_vec();
        self.add_answer_raw(name, 1, ttl, &rdata)?;
        Ok(())
    }

    pub(crate) fn add_aaaa_record(
        &mut self,
        name: &str,
        ttl: u32,
        addr: Ipv6Addr,
    ) -> Result<(), XfrError> {
        let rdata = addr.octets().to_vec();
        self.add_answer_raw(name, 28, ttl, &rdata)?;
        Ok(())
    }

    pub(crate) fn add_cname_record(
        &mut self,
        name: &str,
        ttl: u32,
        target: &str,
    ) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 5, ttl, &rdata)?;
        Ok(())
    }

    pub(crate) fn add_mx_record(
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

    pub(crate) fn add_srv_record(
        &mut self,
        name: &str,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: &str,
    ) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 33, ttl, &rdata)?;
        Ok(())
    }

    pub(crate) fn add_ns_record(
        &mut self,
        name: &str,
        ttl: u32,
        target: &str,
    ) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 2, ttl, &rdata)?;
        Ok(())
    }

    pub(crate) fn add_txt_record(
        &mut self,
        name: &str,
        ttl: u32,
        text: &str,
    ) -> Result<(), XfrError> {
        if let Some(rdata) = txt::decode_raw_txt_rdata(text) {
            self.add_answer_raw(name, 16, ttl, &rdata)?;
            return Ok(());
        }

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

    pub(crate) fn add_ptr_record(
        &mut self,
        name: &str,
        ttl: u32,
        target: &str,
    ) -> Result<(), XfrError> {
        let mut rdata = Vec::new();
        encode_domain_name(target, &mut rdata)?;
        self.add_answer_raw(name, 12, ttl, &rdata)?;
        Ok(())
    }

    /// Adds the catalog-zone NS record, which is the placeholder "invalid".
    pub(crate) fn add_catalog_ns(&mut self, zone: &Zone) -> Result<(), XfrError> {
        let owner_name = to_fqdn(&zone.name);
        self.add_ns_record(&owner_name, zone.ttl as u32, "invalid")?;
        Ok(())
    }

    /// Adds the catalog-zone version TXT record.
    pub(crate) fn add_catalog_version(&mut self, zone: &Zone) -> Result<(), XfrError> {
        let version_name = format!("version.{}.", zone.name.trim_end_matches('.'));
        self.add_txt_record(&version_name, zone.ttl as u32, "2")?;
        Ok(())
    }

    /// Adds a catalog-zone member PTR record.
    pub(crate) fn add_catalog_ptr(
        &mut self,
        zone: &Zone,
        member_zone: &str,
    ) -> Result<(), XfrError> {
        let member_id = crate::server::catalog::zone_name_to_member_id(member_zone);
        let ptr_name = format!("{}.zones.{}.", member_id, zone.name.trim_end_matches('.'));
        let ptr_target = to_fqdn(member_zone);
        self.add_ptr_record(&ptr_name, zone.ttl as u32, &ptr_target)?;
        Ok(())
    }

    /// Adds an answer from a database Record model.
    pub(crate) fn add_record(&mut self, record: &Record, zone_name: &str) -> Result<(), XfrError> {
        let ttl = record.ttl.unwrap_or(3600) as u32;
        let owner_name = to_owner_fqdn(&record.name, zone_name);

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
                let (priority, target) = parse_mx_record_value(&record.value, record.priority)?;
                self.add_mx_record(&owner_name, ttl, priority, target)?;
            }
            "NS" => {
                self.add_ns_record(&owner_name, ttl, &record.value)?;
            }
            "PTR" => {
                self.add_ptr_record(&owner_name, ttl, &record.value)?;
            }
            "SRV" => {
                let (priority, weight, port, target) =
                    parse_srv_record_value(&record.value, record.priority)?;
                self.add_srv_record(&owner_name, ttl, priority, weight, port, target)?;
            }
            "TXT" => {
                self.add_txt_record(&owner_name, ttl, &record.value)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Appends a raw answer record from name, type, TTL, and rdata.
    fn add_answer_raw(
        &mut self,
        name: &str,
        rtype: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Result<(), XfrError> {
        let mut answer = Vec::new();

        encode_domain_name(name, &mut answer)?;
        answer.extend_from_slice(&rtype.to_be_bytes());
        answer.extend_from_slice(&1u16.to_be_bytes()); // CLASS (IN = 1)
        answer.extend_from_slice(&ttl.to_be_bytes());
        answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        answer.extend_from_slice(rdata);

        self.push_answer(answer);
        Ok(())
    }

    pub(crate) fn answer_count(&self) -> usize {
        self.answers.len()
    }

    pub(crate) fn message_len(&self) -> usize {
        12 + self.qname.len() + 4 + self.answers_len
    }

    pub(crate) fn pop_last_answer(&mut self) -> Option<Vec<u8>> {
        let answer = self.answers.pop();
        if let Some(answer) = &answer {
            self.answers_len -= answer.len();
        }
        answer
    }

    pub(crate) fn push_answer(&mut self, answer: Vec<u8>) {
        self.answers_len += answer.len();
        self.answers.push(answer);
    }

    pub(crate) fn clear_answers(&mut self) {
        self.answers.clear();
        self.answers_len = 0;
    }

    fn build_message_into(&self, message: &mut Vec<u8>) {
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
    }

    /// Serializes the header, question, and answers into a DNS message.
    pub(crate) fn build_message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(self.message_len());
        self.build_message_into(&mut message);
        message
    }

    /// Serializes straight into a length-prefixed TCP frame, skipping the
    /// intermediate message buffer `build_message` + `encode_tcp_message`
    /// would copy through.
    pub(crate) fn build_tcp_frame(&self) -> Result<Vec<u8>, XfrError> {
        let len = self.message_len();
        if len > DNS_TCP_MAX_SIZE {
            return Err(XfrError::ProtocolError(format!(
                "Message too large: {} bytes",
                len
            )));
        }

        let mut frame = Vec::with_capacity(2 + len);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
        self.build_message_into(&mut frame);
        Ok(frame)
    }

    /// Consumes the builder and returns the serialized DNS message.
    pub(crate) fn build(self) -> Vec<u8> {
        self.build_message()
    }
}

pub(crate) fn parse_mx_record_value(
    value: &str,
    fallback_priority: Option<i32>,
) -> Result<(u16, &str), XfrError> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    match fields.as_slice() {
        [priority, target] => Ok((parse_u16_field(priority, "MX priority")?, target)),
        [target] => Ok((
            parse_optional_priority(fallback_priority, "MX priority")?,
            target,
        )),
        _ => Err(XfrError::ProtocolError(format!(
            "Invalid MX record value: {value}"
        ))),
    }
}

pub(crate) fn parse_srv_record_value(
    value: &str,
    fallback_priority: Option<i32>,
) -> Result<(u16, u16, u16, &str), XfrError> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    let (priority, weight, port, target) = match fields.as_slice() {
        [priority, weight, port, target] => (
            parse_u16_field(priority, "SRV priority")?,
            *weight,
            *port,
            *target,
        ),
        [weight, port, target] => (
            parse_optional_priority(fallback_priority, "SRV priority")?,
            *weight,
            *port,
            *target,
        ),
        _ => {
            return Err(XfrError::ProtocolError(format!(
                "Invalid SRV record value: {value}"
            )));
        }
    };

    Ok((
        priority,
        parse_u16_field(weight, "SRV weight")?,
        parse_u16_field(port, "SRV port")?,
        target,
    ))
}

fn parse_optional_priority(priority: Option<i32>, field: &str) -> Result<u16, XfrError> {
    u16::try_from(priority.unwrap_or(10))
        .map_err(|_| XfrError::ProtocolError(format!("Invalid {field}")))
}

fn parse_u16_field(value: &str, field: &str) -> Result<u16, XfrError> {
    value
        .parse()
        .map_err(|_| XfrError::ProtocolError(format!("Invalid {field}: {value}")))
}

pub(crate) async fn add_answer_and_flush_if_needed<W, F>(
    writer: &mut W,
    builder: &mut DnsMessageBuilder,
    messages_sent: &mut usize,
    add_answer: F,
) -> Result<(), XfrError>
where
    W: tokio::io::AsyncWriteExt + Unpin,
    F: FnOnce(&mut DnsMessageBuilder) -> Result<(), XfrError>,
{
    add_answer(builder)?;

    if builder.message_len() <= DNS_TCP_MAX_SIZE {
        return Ok(());
    }

    let last_answer = builder.pop_last_answer().ok_or_else(|| {
        XfrError::ProtocolError("DNS message exceeded maximum size without answers".to_string())
    })?;

    if builder.answer_count() == 0 {
        builder.push_answer(last_answer);
        return Err(XfrError::ProtocolError(format!(
            "Single DNS answer is too large: {} bytes",
            builder.message_len()
        )));
    }

    // Count the flush before the size check below, so a caller can tell that
    // bytes reached the client even when this call then returns an error.
    *messages_sent += flush_message_if_not_empty(writer, builder).await?;

    builder.push_answer(last_answer);
    if builder.message_len() > DNS_TCP_MAX_SIZE {
        return Err(XfrError::ProtocolError(format!(
            "Single DNS answer is too large: {} bytes",
            builder.message_len()
        )));
    }

    Ok(())
}

pub(crate) async fn flush_message_if_not_empty<W>(
    writer: &mut W,
    builder: &mut DnsMessageBuilder,
) -> Result<usize, XfrError>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let answer_count = builder.answer_count();
    if answer_count == 0 {
        return Ok(0);
    }

    let frame = builder.build_tcp_frame()?;
    writer.write_all(&frame).await.map_err(XfrError::IoError)?;
    writer.flush().await.map_err(XfrError::IoError)?;
    builder.clear_answers();

    Ok(1)
}

pub(crate) fn build_error_response(
    query_id: u16,
    qname: &Name<Vec<u8>>,
    qtype: Rtype,
    rcode: u8,
) -> Vec<u8> {
    let mut message = Vec::new();

    message.extend_from_slice(&query_id.to_be_bytes());
    message.push(0x80); // QR=1, Opcode=0, AA=0, TC=0, RD=0
    message.push(rcode & 0x0f);
    message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    message.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    message.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    message.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    message.extend_from_slice(qname.as_slice());
    message.extend_from_slice(&qtype.to_int().to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

    message
}

pub(crate) fn encode_domain_name(name: &str, buf: &mut Vec<u8>) -> Result<(), XfrError> {
    let name = name.trim_end_matches('.');

    if name.is_empty() {
        buf.push(0);
        return Ok(());
    }

    for label in presentation_labels(name).map_err(|e| XfrError::ProtocolError(e.to_string()))? {
        if label.is_empty() {
            continue;
        }
        if label.len() > MAX_DNS_LABEL_LEN {
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

/// A DNS query parsed once at the listener and handed to every handler.
pub(crate) struct ParsedQuery {
    pub(crate) qname: Name<Vec<u8>>,
    pub(crate) qtype: Rtype,
    pub(crate) client_serial: Option<u32>,
    pub(crate) query_id: u16,
}

pub(crate) fn parse_query(data: &[u8]) -> Result<ParsedQuery, XfrError> {
    let message = Message::from_octets(data)
        .map_err(|e| XfrError::ProtocolError(format!("Failed to parse DNS message: {}", e)))?;

    let query_id = message.header().id();

    let question = message
        .first_question()
        .ok_or_else(|| XfrError::ProtocolError("No question in DNS query".to_string()))?;

    let qname = question.qname().to_name::<Vec<u8>>();
    let qtype = question.qtype();

    // An IXFR query carries the client's current serial in an
    // authority-section SOA (RFC 1995 §2).
    let client_serial = if qtype == Rtype::IXFR {
        extract_ixfr_serial(&message)
    } else {
        None
    };

    Ok(ParsedQuery {
        qname,
        qtype,
        client_serial,
        query_id,
    })
}

fn extract_ixfr_serial(message: &Message<&[u8]>) -> Option<u32> {
    message
        .authority()
        .ok()?
        .limit_to::<Soa<_>>()
        .find_map(|record| record.ok())
        .map(|record| record.data().serial().into_int())
}

pub(crate) fn encode_tcp_message(message: &[u8]) -> Result<Vec<u8>, XfrError> {
    if message.len() > DNS_TCP_MAX_SIZE {
        return Err(XfrError::ProtocolError(format!(
            "Message too large: {} bytes",
            message.len()
        )));
    }

    let len = message.len() as u16;
    let mut result = Vec::with_capacity(2 + message.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(message);
    Ok(result)
}

pub(crate) async fn read_tcp_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, XfrError> {
    let mut len_buf = [0u8; 2];
    if reader
        .read(&mut len_buf[..1])
        .await
        .map_err(XfrError::IoError)?
        == 0
    {
        return Err(XfrError::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed",
        )));
    }
    reader.read_exact(&mut len_buf[1..]).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            XfrError::ProtocolError("Incomplete DNS TCP length prefix".to_string())
        } else {
            XfrError::IoError(e)
        }
    })?;

    let len = u16::from_be_bytes(len_buf) as usize;

    if len > DNS_TCP_MAX_SIZE {
        return Err(XfrError::ProtocolError(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut message_buf = vec![0u8; len];
    reader.read_exact(&mut message_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            XfrError::ProtocolError(format!(
                "Incomplete DNS TCP message: expected {} bytes",
                len
            ))
        } else {
            XfrError::IoError(e)
        }
    })?;

    Ok(message_buf)
}

pub(crate) async fn write_tcp_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), XfrError> {
    let encoded = encode_tcp_message(message)?;
    writer
        .write_all(&encoded)
        .await
        .map_err(XfrError::IoError)?;
    writer.flush().await.map_err(XfrError::IoError)?;

    Ok(())
}

#[cfg(test)]
mod tests;
