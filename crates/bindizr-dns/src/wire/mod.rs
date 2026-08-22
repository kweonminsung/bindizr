//! DNS wire-format encoding for zone-transfer responses: message framing and
//! record/SOA serialization.

use bindizr_core::dns::{
    name::{OwnerName, ParseNameError, ZoneName, encode_name, to_fqdn},
    record::{EncodedRdata, Rdata, SoaRecordValue},
};
use domain::{
    base::{
        Message, MessageBuilder, Name, ToName, Ttl, UnknownRecordData,
        iana::{Class, Rcode, Rtype},
        rdata::ComposeRecordData,
        record::ComposeRecord,
    },
    rdata::Soa,
};

use crate::{
    error::XfrError,
    log_warn,
    model::{
        dnssec_record::DnssecRecord,
        record::{Record, RecordType},
        zone::Zone,
    },
};

/// Maximum size of a DNS message carried over TCP (16-bit length prefix).
const DNS_TCP_MAX_SIZE: usize = 65535;

/// What [`DnsMessageBuilder::add_raw_rdata`] accepts as its owner: a parsed
/// name, or a typed name's wire bytes still carrying their encoding error.
pub(crate) trait IntoOwner {
    fn into_owner(self) -> Result<Name<Vec<u8>>, XfrError>;
}

impl IntoOwner for Name<Vec<u8>> {
    fn into_owner(self) -> Result<Name<Vec<u8>>, XfrError> {
        Ok(self)
    }
}

impl IntoOwner for Result<Vec<u8>, ParseNameError> {
    fn into_owner(self) -> Result<Name<Vec<u8>>, XfrError> {
        let wire =
            self.map_err(|e| XfrError::ProtocolError(format!("invalid owner name: {}", e)))?;
        Name::from_octets(wire)
            .map_err(|e| XfrError::ProtocolError(format!("invalid owner name: {}", e)))
    }
}

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
        let rdata = zone.soa_rdata(serial).map_err(XfrError::ProtocolError)?;
        self.add_raw_rdata(
            zone.name.to_wire(),
            RecordType::SOA.wire_type(),
            zone.default_ttl as u32,
            rdata,
        )
    }

    /// Adds a catalog-zone SOA with placeholder `invalid` MNAME/RNAME.
    pub(crate) fn add_catalog_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), XfrError> {
        let rdata = SoaRecordValue {
            mname: "invalid",
            rname: "invalid",
            serial,
            refresh: zone.refresh as u32,
            retry: zone.retry as u32,
            expire: zone.expire as u32,
            minimum: zone.minimum_ttl as u32,
        }
        .to_rdata()
        .map_err(XfrError::ProtocolError)?;
        self.add_raw_rdata(
            zone.name.to_wire(),
            RecordType::SOA.wire_type(),
            zone.default_ttl as u32,
            rdata,
        )
    }

    /// Adds an SOA from a serial-specific version.
    pub(crate) fn add_version_soa(
        &mut self,
        soa: &crate::server::delta::ZoneVersion,
    ) -> Result<(), XfrError> {
        let serial = crate::server::delta::serial_to_u32(soa.serial)?;
        let rdata = SoaRecordValue {
            mname: &soa.mname,
            rname: &soa.rname,
            serial,
            refresh: soa.refresh as u32,
            retry: soa.retry as u32,
            expire: soa.expire as u32,
            minimum: soa.minimum_ttl as u32,
        }
        .to_rdata()
        .map_err(XfrError::ProtocolError)?;

        // IXFR SOA owner is the transfer QNAME.
        self.add_raw_rdata(
            self.qname.clone(),
            RecordType::SOA.wire_type(),
            soa.default_ttl as u32,
            rdata,
        )
    }

    /// Adds one answer of any supported stored type at an absolute owner name.
    fn add_text_rdata(
        &mut self,
        name: &str,
        ttl: u32,
        record_type: &RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> Result<(), XfrError> {
        match EncodedRdata::from_columns(record_type, value, priority) {
            Ok(Some(EncodedRdata { record_type, rdata })) => {
                self.add_raw_rdata(parse_name(name)?, record_type, ttl, rdata)
            }
            Ok(None) => {
                log_warn!(
                    "Dropping record of unsupported type {} from transfer",
                    record_type
                );
                Ok(())
            }
            Err(e) => Err(XfrError::ProtocolError(e)),
        }
    }

    /// Adds the catalog-zone NS record, which is the placeholder "invalid".
    pub(crate) fn add_catalog_ns(&mut self, zone: &Zone) -> Result<(), XfrError> {
        let owner_name = zone.name.to_fqdn();
        self.add_text_rdata(
            &owner_name,
            zone.default_ttl as u32,
            &RecordType::NS,
            "invalid",
            None,
        )
    }

    /// Adds the catalog-zone version TXT record.
    pub(crate) fn add_catalog_schema_version(&mut self, zone: &Zone) -> Result<(), XfrError> {
        let version_name = format!("version.{}.", zone.name);
        // "2" is the RFC 9432 catalog zone schema version.
        self.add_text_rdata(
            &version_name,
            zone.default_ttl as u32,
            &RecordType::TXT,
            "2",
            None,
        )
    }

    /// Adds a catalog-zone member PTR record.
    pub(crate) fn add_catalog_ptr(
        &mut self,
        zone: &Zone,
        member_zone: &str,
    ) -> Result<(), XfrError> {
        let member_id = crate::server::catalog::zone_name_to_member_id(member_zone);
        let ptr_name = format!("{}.zones.{}.", member_id, zone.name);
        let ptr_target = to_fqdn(member_zone);
        self.add_text_rdata(
            &ptr_name,
            zone.default_ttl as u32,
            &RecordType::PTR,
            &ptr_target,
            None,
        )
    }

    /// Adds an answer from a database Record model.
    pub(crate) fn add_record(
        &mut self,
        record: &Record,
        zone_name: &ZoneName,
    ) -> Result<(), XfrError> {
        self.add_record_parts(
            zone_name,
            &record.name,
            &record.record_type,
            &record.value,
            record.ttl,
            record.priority,
        )
    }

    /// Adds an answer from stored record columns (records and journal
    /// rows share this shape). Unsupported types are skipped.
    pub(crate) fn add_record_parts(
        &mut self,
        zone_name: &ZoneName,
        name: &OwnerName,
        record_type: &RecordType,
        value: &str,
        ttl: i32,
        priority: Option<i32>,
    ) -> Result<(), XfrError> {
        match EncodedRdata::from_columns(record_type, value, priority)
            .map_err(XfrError::ProtocolError)?
        {
            Some(EncodedRdata { record_type, rdata }) => {
                self.add_raw_rdata(name.to_wire(zone_name), record_type, ttl as u32, rdata)
            }
            None => {
                log_warn!(
                    "Dropping record of unsupported type {} from transfer",
                    record_type
                );
                Ok(())
            }
        }
    }

    /// Adds a derived DNSSEC record; its RDATA is stored in wire form.
    pub(crate) fn add_dnssec_record(
        &mut self,
        record: &DnssecRecord,
        zone_name: &ZoneName,
    ) -> Result<(), XfrError> {
        self.add_raw_rdata(
            record.name.to_wire(zone_name),
            record.record_type.wire_type(),
            record.ttl as u32,
            record.rdata.clone(),
        )
    }

    /// Adds an answer from wire-format RDATA bytes, with no per-type parser.
    pub(crate) fn add_raw_rdata(
        &mut self,
        owner: impl IntoOwner,
        record_type: u16,
        ttl: u32,
        rdata: Rdata,
    ) -> Result<(), XfrError> {
        let data = UnknownRecordData::from_octets(Rtype::from_int(record_type), rdata.into_bytes())
            .map_err(|e| XfrError::ProtocolError(format!("Invalid raw rdata: {}", e)))?;
        self.add_answer(owner.into_owner()?, ttl, data);
        Ok(())
    }

    /// Composes one class-IN answer RR into its own buffer so it can be
    /// popped/reflushed by the chunked TCP writer.
    fn add_answer<N: ToName, D: ComposeRecordData>(&mut self, owner: N, ttl: u32, data: D) {
        let record = domain::base::Record::new(owner, Class::IN, Ttl::from_secs(ttl), data);
        let mut answer = Vec::new();
        // Composing into a Vec is infallible.
        record
            .compose_record(&mut answer)
            .expect("composing into a Vec cannot run out of space");
        self.push_answer(answer);
    }

    fn answer_count(&self) -> usize {
        self.answers.len()
    }

    fn message_len(&self) -> usize {
        12 + self.qname.len() + 4 + self.answers_len
    }

    fn pop_last_answer(&mut self) -> Option<Vec<u8>> {
        let answer = self.answers.pop();
        if let Some(answer) = &answer {
            self.answers_len -= answer.len();
        }
        answer
    }

    fn push_answer(&mut self, answer: Vec<u8>) {
        self.answers_len += answer.len();
        self.answers.push(answer);
    }

    fn clear_answers(&mut self) {
        self.answers.clear();
        self.answers_len = 0;
    }

    pub(crate) async fn add_answer_and_flush_if_needed<W, F>(
        &mut self,
        writer: &mut W,
        messages_sent: &mut usize,
        add_answer: F,
    ) -> Result<(), XfrError>
    where
        W: tokio::io::AsyncWriteExt + Unpin,
        F: FnOnce(&mut DnsMessageBuilder) -> Result<(), XfrError>,
    {
        add_answer(self)?;

        if self.message_len() <= DNS_TCP_MAX_SIZE {
            return Ok(());
        }

        let last_answer = self.pop_last_answer().ok_or_else(|| {
            XfrError::ProtocolError("DNS message exceeded maximum size without answers".to_string())
        })?;

        if self.answer_count() == 0 {
            self.push_answer(last_answer);
            return Err(XfrError::ProtocolError(format!(
                "Single DNS answer is too large: {} bytes",
                self.message_len()
            )));
        }

        // Count the flush before the size check below so a caller can tell that
        // bytes reached the client even when this call then returns an error.
        *messages_sent += self.flush_if_not_empty(writer).await?;

        self.push_answer(last_answer);
        if self.message_len() > DNS_TCP_MAX_SIZE {
            return Err(XfrError::ProtocolError(format!(
                "Single DNS answer is too large: {} bytes",
                self.message_len()
            )));
        }

        Ok(())
    }

    pub(crate) async fn flush_if_not_empty<W>(&mut self, writer: &mut W) -> Result<usize, XfrError>
    where
        W: tokio::io::AsyncWriteExt + Unpin,
    {
        let answer_count = self.answer_count();
        if answer_count == 0 {
            return Ok(0);
        }

        let frame = self.build_tcp_frame()?;
        writer.write_all(&frame).await.map_err(XfrError::IoError)?;
        writer.flush().await.map_err(XfrError::IoError)?;
        self.clear_answers();

        Ok(1)
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
    fn build_tcp_frame(&self) -> Result<Vec<u8>, XfrError> {
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

/// Parses a presentation-form name through the one core name encoding.
fn parse_name(name: &str) -> Result<Name<Vec<u8>>, XfrError> {
    let wire = encode_name(name).map_err(XfrError::ProtocolError)?;
    Name::from_octets(wire)
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

impl ParsedQuery {
    pub(crate) fn parse(data: &[u8]) -> Result<ParsedQuery, XfrError> {
        let message = Message::from_octets(data)
            .map_err(|e| XfrError::ProtocolError(format!("Failed to parse DNS message: {}", e)))?;

        let query_id = message.header().id();

        let question = message
            .first_question()
            .ok_or_else(|| XfrError::ProtocolError("No question in DNS query".to_string()))?;

        let qname = question.qname().to_name::<Vec<u8>>();
        let qtype = question.qtype();

        // domain's `Display` renders the root as "." and otherwise omits the
        // root dot, so only the root query maps to the empty zone form; a
        // trailing escaped dot inside the last label stays data.
        let qname_presentation = qname.to_string();
        let zone_name = if qname_presentation == "." {
            String::new()
        } else {
            qname_presentation
        };

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

    /// A response echoing this query with only `rcode` set.
    pub(crate) fn error_response(&self, rcode: Rcode) -> Vec<u8> {
        let mut builder = MessageBuilder::new_vec();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);
        header.set_rcode(rcode);

        let mut question = builder.question();
        // Composing one question into a Vec cannot fail.
        question
            .push((&self.qname, self.qtype))
            .expect("composing into a Vec cannot run out of space");

        question.finish()
    }
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
