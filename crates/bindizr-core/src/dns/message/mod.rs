//! DNS wire-format encoding for zone-transfer responses: message framing and
//! record/SOA serialization.

pub use domain::base::{
    Name,
    iana::{Class, Opcode, Rcode, Rtype},
};
use domain::{
    base::{
        Message, MessageBuilder, ToName, Ttl, UnknownRecordData, rdata::ComposeRecordData,
        record::ComposeRecord,
    },
    rdata::Soa,
};

use crate::{
    dns::{
        DNS_TCP_MAX_SIZE,
        name::{OwnerName, ParseNameError, ZoneName, encode_name, to_fqdn},
        record::{EncodedRdata, Rdata, SoaRecordValue, TxtRecordValue},
    },
    model::{
        dnssec_record::DnssecRecord,
        record::{Record, RecordType},
        zone::Zone,
    },
};

/// A size failure that may still carry a frame: the caller must send it so
/// its message count reflects what reached the client before the failure.
pub struct Overflow {
    /// The answers buffered before the oversized one, if there were any.
    pub frame: Option<Vec<u8>>,
    pub message: String,
}

impl Overflow {
    fn without_frame(message: String) -> Self {
        Overflow {
            frame: None,
            message,
        }
    }
}

/// RR TYPE number of SOA (RFC 1035); SOA never appears as a stored record
/// row, so `RecordType` does not spell it.
const SOA_WIRE_TYPE: u16 = 6;

/// What [`DnsMessageBuilder::add_raw_rdata`] accepts as its owner: a parsed
/// name, or a typed name's wire bytes still carrying their encoding error.
pub trait IntoOwner {
    fn into_owner(self) -> Result<Name<Vec<u8>>, String>;
}

impl IntoOwner for Name<Vec<u8>> {
    fn into_owner(self) -> Result<Name<Vec<u8>>, String> {
        Ok(self)
    }
}

impl IntoOwner for Result<Vec<u8>, ParseNameError> {
    fn into_owner(self) -> Result<Name<Vec<u8>>, String> {
        let wire = self.map_err(|e| format!("invalid owner name: {}", e))?;
        Name::from_octets(wire).map_err(|e| format!("invalid owner name: {}", e))
    }
}

pub struct DnsMessageBuilder {
    query_id: u16,
    qname: Name<Vec<u8>>,
    qtype: u16,
    answers: Vec<Vec<u8>>,
    /// Total byte length of `answers`, maintained incrementally for `message_len`.
    answers_len: usize,
}

impl DnsMessageBuilder {
    pub fn new(query_id: u16, qname: &Name<Vec<u8>>, qtype: Rtype) -> Self {
        Self {
            query_id,
            qname: qname.clone(),
            qtype: qtype.to_int(),
            answers: Vec::new(),
            answers_len: 0,
        }
    }

    pub fn add_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), String> {
        let rdata = zone.soa_rdata(serial)?;
        self.add_raw_rdata(
            zone.name.to_wire(),
            SOA_WIRE_TYPE,
            zone.default_ttl as u32,
            rdata,
        )
    }

    /// Adds a catalog-zone SOA with placeholder `invalid` MNAME/RNAME.
    pub fn add_catalog_soa(&mut self, zone: &Zone, serial: u32) -> Result<(), String> {
        let rdata = SoaRecordValue {
            mname: "invalid",
            rname: "invalid",
            serial,
            refresh: zone.refresh as u32,
            retry: zone.retry as u32,
            expire: zone.expire as u32,
            minimum: zone.minimum_ttl as u32,
        }
        .to_rdata()?;
        self.add_raw_rdata(
            zone.name.to_wire(),
            SOA_WIRE_TYPE,
            zone.default_ttl as u32,
            rdata,
        )
    }

    /// Adds an SOA from a serial-specific version.
    pub fn add_version_soa(
        &mut self,
        soa: &crate::model::zone_version::ZoneVersion,
    ) -> Result<(), String> {
        let serial = crate::dns::serial_to_u32(soa.serial)?;
        let rdata = SoaRecordValue {
            mname: &soa.mname,
            rname: &soa.rname,
            serial,
            refresh: soa.refresh as u32,
            retry: soa.retry as u32,
            expire: soa.expire as u32,
            minimum: soa.minimum_ttl as u32,
        }
        .to_rdata()?;

        // IXFR SOA owner is the transfer QNAME.
        self.add_raw_rdata(
            self.qname.clone(),
            SOA_WIRE_TYPE,
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
    ) -> Result<(), String> {
        match EncodedRdata::from_columns(record_type, value, priority) {
            Ok(EncodedRdata { record_type, rdata }) => {
                self.add_raw_rdata(parse_name(name)?, record_type, ttl, rdata)
            }
            Err(e) => Err(e),
        }
    }

    /// Adds the catalog-zone NS record, which is the placeholder "invalid".
    pub fn add_catalog_ns(&mut self, zone: &Zone) -> Result<(), String> {
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
    pub fn add_catalog_schema_version(&mut self, zone: &Zone) -> Result<(), String> {
        let version_name = format!("version.{}.", zone.name);
        // "2" is the RFC 9432 catalog zone schema version.
        self.add_text_rdata(
            &version_name,
            zone.default_ttl as u32,
            &RecordType::TXT,
            &TxtRecordValue::from_string("2").to_presentation(),
            None,
        )
    }

    /// Adds a catalog-zone member PTR record.
    pub fn add_catalog_ptr(&mut self, zone: &Zone, member_zone: &str) -> Result<(), String> {
        let member_id = crate::dns::zone_name_to_member_id(member_zone);
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
    pub fn add_record(&mut self, record: &Record, zone_name: &ZoneName) -> Result<(), String> {
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
    pub fn add_record_parts(
        &mut self,
        zone_name: &ZoneName,
        name: &OwnerName,
        record_type: &RecordType,
        value: &str,
        ttl: i32,
        priority: Option<i32>,
    ) -> Result<(), String> {
        let EncodedRdata { record_type, rdata } =
            EncodedRdata::from_columns(record_type, value, priority)?;
        self.add_raw_rdata(name.to_wire(zone_name), record_type, ttl as u32, rdata)
    }

    /// Adds a derived DNSSEC record; its RDATA is stored in wire form.
    pub fn add_dnssec_record(
        &mut self,
        record: &DnssecRecord,
        zone_name: &ZoneName,
    ) -> Result<(), String> {
        self.add_raw_rdata(
            record.name.to_wire(zone_name),
            record.record_type.wire_type(),
            record.ttl as u32,
            record.rdata.clone(),
        )
    }

    /// Adds an answer from wire-format RDATA bytes, with no per-type parser.
    pub fn add_raw_rdata(
        &mut self,
        owner: impl IntoOwner,
        record_type: u16,
        ttl: u32,
        rdata: Rdata,
    ) -> Result<(), String> {
        let data = UnknownRecordData::from_octets(Rtype::from_int(record_type), rdata.into_bytes())
            .map_err(|e| format!("Invalid raw rdata: {}", e))?;
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

    /// Buffer one answer. When it would push the message past the TCP size
    /// limit, the answers buffered before it are returned as a ready frame and
    /// the new answer stays buffered for the next one.
    pub fn add_answer_or_overflow<F>(&mut self, add_answer: F) -> Result<Option<Vec<u8>>, Overflow>
    where
        F: FnOnce(&mut DnsMessageBuilder) -> Result<(), String>,
    {
        add_answer(self).map_err(Overflow::without_frame)?;

        if self.message_len() <= DNS_TCP_MAX_SIZE {
            return Ok(None);
        }

        let last_answer = self.pop_last_answer().ok_or_else(|| {
            Overflow::without_frame("DNS message exceeded maximum size without answers".to_string())
        })?;

        if self.answer_count() == 0 {
            self.push_answer(last_answer);
            return Err(Overflow::without_frame(self.too_large_message()));
        }

        let frame = self.take_frame().map_err(Overflow::without_frame)?;

        self.push_answer(last_answer);
        if self.message_len() > DNS_TCP_MAX_SIZE {
            return Err(Overflow {
                frame,
                message: self.too_large_message(),
            });
        }

        Ok(frame)
    }

    /// The buffered answers as a length-prefixed TCP frame, clearing them;
    /// `None` when nothing is buffered.
    pub fn take_frame(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.answer_count() == 0 {
            return Ok(None);
        }
        let frame = self.build_tcp_frame()?;
        self.clear_answers();
        Ok(Some(frame))
    }

    fn too_large_message(&self) -> String {
        format!(
            "Single DNS answer is too large: {} bytes",
            self.message_len()
        )
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
    fn build_tcp_frame(&self) -> Result<Vec<u8>, String> {
        let len = self.message_len();
        if len > DNS_TCP_MAX_SIZE {
            return Err(format!("Message too large: {} bytes", len));
        }

        let mut frame = Vec::with_capacity(2 + len);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
        self.build_message_into(&mut frame);
        Ok(frame)
    }

    /// Consumes the builder and returns the serialized DNS message.
    pub fn build(self) -> Vec<u8> {
        let mut message = Vec::with_capacity(self.message_len());
        self.build_message_into(&mut message);
        message
    }
}

/// Parses a presentation-form name through the one core name encoding.
fn parse_name(name: &str) -> Result<Name<Vec<u8>>, String> {
    let wire = encode_name(name)?;
    Name::from_octets(wire).map_err(|e| format!("Invalid domain name '{}': {}", name, e))
}

/// A DNS query parsed once at the listener and handed to every handler.
pub struct ParsedQuery {
    pub qname: Name<Vec<u8>>,
    /// Presentation form of `qname` without the trailing dot.
    pub zone_name: String,
    pub qtype: Rtype,
    pub client_serial: Option<u32>,
    pub query_id: u16,
}

impl ParsedQuery {
    pub fn parse(data: &[u8]) -> Result<ParsedQuery, String> {
        let message = Message::from_octets(data)
            .map_err(|e| format!("Failed to parse DNS message: {}", e))?;

        let query_id = message.header().id();

        let question = message
            .first_question()
            .ok_or_else(|| "No question in DNS query".to_string())?;

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
    pub fn error_response(&self, rcode: Rcode) -> Vec<u8> {
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

pub fn encode_tcp_message(message: &[u8]) -> Result<Vec<u8>, String> {
    if message.len() > DNS_TCP_MAX_SIZE {
        return Err(format!("Message too large: {} bytes", message.len()));
    }

    let len = message.len() as u16;
    let mut result = Vec::with_capacity(2 + message.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(message);
    Ok(result)
}

#[cfg(test)]
mod tests;
