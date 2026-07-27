//! DNS wire-format encoding for zone-transfer responses: message framing and
//! record/SOA serialization.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use bindizr_core::dns::name::{email_to_soa_mailbox, to_fqdn, to_owner_fqdn};
use domain::{
    base::{
        Message, MessageBuilder, Name, Serial, ToName, Ttl, UnknownRecordData,
        iana::{Class, Rcode, Rtype},
        rdata::ComposeRecordData,
        record::ComposeRecord,
    },
    rdata::{A, Aaaa, Cname, Mx, Ns, Ptr, Soa, Srv, Txt},
};

use crate::{
    error::XfrError,
    log_info,
    model::{record::Record, zone::Zone},
    txt,
};

/// Maximum size of a DNS message carried over TCP (16-bit length prefix).
const DNS_TCP_MAX_SIZE: usize = 65535;

pub(crate) struct DnsMessageBuilder {
    query_id: u16,
    qname: Name<Vec<u8>>,
    qtype: u16,
    answers: Vec<Vec<u8>>,
    /// Total byte length of `answers`, maintained incrementally for `message_len`.
    answers_len: usize,
}

impl DnsMessageBuilder {
    pub(crate) fn new(query_id: u16, qname: &Name<Vec<u8>>, qtype: Rtype) -> Self {
        Self {
            query_id,
            qname: qname.clone(),
            qtype: qtype.to_int(),
            answers: Vec::new(),
            answers_len: 0,
        }
    }

    pub(crate) fn add_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), XfrError> {
        let admin_email = email_to_soa_mailbox(&zone.admin_email)
            .map_err(|e| XfrError::ProtocolError(e.to_string()))?;
        let soa = Soa::new(
            parse_name(&zone.primary_ns)?,
            parse_name(&admin_email)?,
            Serial(serial),
            Ttl::from_secs(zone.refresh as u32),
            Ttl::from_secs(zone.retry as u32),
            Ttl::from_secs(zone.expire as u32),
            Ttl::from_secs(zone.minimum_ttl as u32),
        );
        self.add_answer(parse_name(&zone.name)?, zone.ttl as u32, soa);
        Ok(())
    }

    /// Adds a catalog-zone SOA with placeholder `invalid` MNAME/RNAME.
    pub(crate) fn add_catalog_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), XfrError> {
        let soa = Soa::new(
            parse_name("invalid")?,
            parse_name("invalid")?,
            Serial(serial),
            Ttl::from_secs(zone.refresh as u32),
            Ttl::from_secs(zone.retry as u32),
            Ttl::from_secs(zone.expire as u32),
            Ttl::from_secs(zone.minimum_ttl as u32),
        );
        self.add_answer(parse_name(&zone.name)?, zone.ttl as u32, soa);
        Ok(())
    }

    /// Adds an SOA from a serial-specific snapshot.
    pub(crate) fn add_soa_from_snapshot(
        &mut self,
        soa: &crate::server::delta::ZoneSnapshot,
    ) -> Result<(), XfrError> {
        let serial = crate::server::delta::serial_to_u32(soa.serial)?;
        let rdata = Soa::new(
            parse_name(&soa.primary_ns)?,
            parse_name(&soa.admin_email)?,
            Serial(serial),
            Ttl::from_secs(soa.refresh as u32),
            Ttl::from_secs(soa.retry as u32),
            Ttl::from_secs(soa.expire as u32),
            Ttl::from_secs(soa.minimum_ttl as u32),
        );

        // IXFR SOA owner is the transfer QNAME.
        self.add_answer(self.qname.clone(), soa.ttl as u32, rdata);
        Ok(())
    }

    pub(crate) fn add_a_record(
        &mut self,
        name: &str,
        ttl: u32,
        addr: Ipv4Addr,
    ) -> Result<(), XfrError> {
        self.add_answer(parse_name(name)?, ttl, A::new(addr));
        Ok(())
    }

    pub(crate) fn add_aaaa_record(
        &mut self,
        name: &str,
        ttl: u32,
        addr: Ipv6Addr,
    ) -> Result<(), XfrError> {
        self.add_answer(parse_name(name)?, ttl, Aaaa::new(addr));
        Ok(())
    }

    pub(crate) fn add_cname_record(
        &mut self,
        name: &str,
        ttl: u32,
        target: &str,
    ) -> Result<(), XfrError> {
        self.add_answer(parse_name(name)?, ttl, Cname::new(parse_name(target)?));
        Ok(())
    }

    pub(crate) fn add_mx_record(
        &mut self,
        name: &str,
        ttl: u32,
        priority: u16,
        target: &str,
    ) -> Result<(), XfrError> {
        self.add_answer(
            parse_name(name)?,
            ttl,
            Mx::new(priority, parse_name(target)?),
        );
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
        let srv = Srv::new(priority, weight, port, parse_name(target)?);
        self.add_answer(parse_name(name)?, ttl, srv);
        Ok(())
    }

    pub(crate) fn add_ns_record(
        &mut self,
        name: &str,
        ttl: u32,
        target: &str,
    ) -> Result<(), XfrError> {
        self.add_answer(parse_name(name)?, ttl, Ns::new(parse_name(target)?));
        Ok(())
    }

    pub(crate) fn add_txt_record(
        &mut self,
        name: &str,
        ttl: u32,
        text: &str,
    ) -> Result<(), XfrError> {
        let owner = parse_name(name)?;

        // Operator-supplied raw rdata is passed through unchanged.
        if let Some(rdata) = txt::decode_raw_txt_rdata(text) {
            let data = UnknownRecordData::from_octets(Rtype::TXT, rdata)
                .map_err(|e| XfrError::ProtocolError(format!("Invalid TXT rdata: {}", e)))?;
            self.add_answer(owner, ttl, data);
            return Ok(());
        }

        let data = Txt::<Vec<u8>>::build_from_slice(text.as_bytes())
            .map_err(|e| XfrError::ProtocolError(format!("Invalid TXT value: {}", e)))?;
        self.add_answer(owner, ttl, data);
        Ok(())
    }

    pub(crate) fn add_ptr_record(
        &mut self,
        name: &str,
        ttl: u32,
        target: &str,
    ) -> Result<(), XfrError> {
        self.add_answer(parse_name(name)?, ttl, Ptr::new(parse_name(target)?));
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
        // "2" is the RFC 9432 catalog zone schema version.
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
        self.add_record_parts(
            zone_name,
            &record.name,
            record.record_type.as_str(),
            &record.value,
            record.ttl,
            record.priority,
        )
    }

    /// Adds an answer from stored record columns (records and IXFR zone
    /// changes share this shape). Unsupported types are skipped.
    pub(crate) fn add_record_parts(
        &mut self,
        zone_name: &str,
        name: &str,
        record_type: &str,
        value: &str,
        ttl: i32,
        priority: Option<i32>,
    ) -> Result<(), XfrError> {
        let ttl = ttl as u32;
        let owner_name = to_owner_fqdn(name, zone_name);

        match record_type {
            "A" => {
                let addr: Ipv4Addr = value
                    .parse()
                    .map_err(|_| XfrError::ProtocolError(format!("Invalid A record: {}", value)))?;
                self.add_a_record(&owner_name, ttl, addr)
            }
            "AAAA" => {
                let addr: Ipv6Addr = value.parse().map_err(|_| {
                    XfrError::ProtocolError(format!("Invalid AAAA record: {}", value))
                })?;
                self.add_aaaa_record(&owner_name, ttl, addr)
            }
            "CNAME" => self.add_cname_record(&owner_name, ttl, value),
            "MX" => {
                let (mx_priority, target) = parse_mx_record_value(value, priority)?;
                self.add_mx_record(&owner_name, ttl, mx_priority, target)
            }
            "NS" => self.add_ns_record(&owner_name, ttl, value),
            "PTR" => self.add_ptr_record(&owner_name, ttl, value),
            "SRV" => {
                let (srv_priority, weight, port, target) = parse_srv_record_value(value, priority)?;
                self.add_srv_record(&owner_name, ttl, srv_priority, weight, port, target)
            }
            "TXT" => self.add_txt_record(&owner_name, ttl, value),
            other => {
                log_info!("Skipping unsupported record type: {}", other);
                Ok(())
            }
        }
    }

    /// Composes one class-IN answer RR into its own buffer so it can be
    /// popped/reflushed by the chunked TCP writer.
    fn add_answer<N: ToName, D: ComposeRecordData>(&mut self, owner: N, ttl: u32, data: D) {
        let record = domain::base::Record::new(owner, Class::IN, Ttl::from_secs(ttl), data);
        let mut answer = Vec::new();
        // Composing into a Vec is infallible.
        record.compose_record(&mut answer).unwrap();
        self.push_answer(answer);
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
        message.extend_from_slice(&self.query_id.to_be_bytes()); // ID
        message.push(0x84); // QR=1, Opcode=0, AA=1, TC=0, RD=0
        message.push(0x00); // RA=0, Z=0, RCODE=0 (NOERROR)
        message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        message.extend_from_slice(&(self.answers.len() as u16).to_be_bytes()); // ANCOUNT
        message.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
        message.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

        message.extend_from_slice(self.qname.as_slice());
        message.extend_from_slice(&self.qtype.to_be_bytes()); // QTYPE
        message.extend_from_slice(&1u16.to_be_bytes()); // QCLASS (IN)

        for answer in &self.answers {
            message.extend_from_slice(answer);
        }
    }

    /// Serializes into a length-prefixed TCP frame in one buffer, with no
    /// intermediate message copy.
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
        let mut message = Vec::with_capacity(self.message_len());
        self.build_message_into(&mut message);
        message
    }
}

fn parse_mx_record_value(
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

fn parse_srv_record_value(
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

    // Count the flush before the size check below so a caller can tell that
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
    rcode: Rcode,
) -> Vec<u8> {
    let mut builder = MessageBuilder::new_vec();
    let header = builder.header_mut();
    header.set_id(query_id);
    header.set_qr(true);
    header.set_rcode(rcode);

    let mut question = builder.question();
    // Composing one question into a Vec cannot fail.
    question.push((qname, qtype)).unwrap();

    question.finish()
}

/// Parses a presentation-form name, mapping empty/root input to the root name.
fn parse_name(name: &str) -> Result<Name<Vec<u8>>, XfrError> {
    if name.trim_end_matches('.').is_empty() {
        return Ok(Name::root_vec());
    }

    Name::from_str(name)
        .map_err(|e| XfrError::ProtocolError(format!("Invalid domain name '{}': {}", name, e)))
}

/// A DNS query parsed once at the listener and handed to every handler.
pub(crate) struct ParsedQuery {
    pub(crate) qname: Name<Vec<u8>>,
    /// Presentation form of `qname` without the trailing dot.
    pub(crate) zone_name: String,
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

    let qname_presentation = qname.to_string();
    let zone_name = qname_presentation.trim_end_matches('.').to_string();

    // An IXFR query carries the client's current serial in an
    // authority-section SOA (RFC 1995, Section 2).
    let client_serial = if qtype == Rtype::IXFR {
        extract_ixfr_serial(&message)
    } else {
        None
    };

    Ok(ParsedQuery {
        qname,
        zone_name,
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
