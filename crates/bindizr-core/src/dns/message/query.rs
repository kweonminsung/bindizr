//! Reading an inbound query: what the listener parses once and hands to every
//! handler, and the short replies it answers without touching the zone.

use domain::{
    base::{
        Header, Message, MessageBuilder, Name, Rtype, ToName,
        iana::{Opcode, Rcode},
        message_builder::QuestionBuilder,
    },
    rdata::{Soa, tsig::Time48},
};

use crate::dns::tsig::TransferSigner;

/// Whether the message is itself a response (QR=1). Answering one lets a
/// spoofed source aim the reply at a third party.
pub fn is_response(message: &[u8]) -> bool {
    Message::from_octets(message).is_ok_and(|message| message.header().qr())
}

/// A DNS query parsed once at the listener and handed to every handler.
pub struct ParsedQuery {
    pub qname: Name<Vec<u8>>,
    /// Presentation form of `qname` without the trailing dot.
    pub zone_name: String,
    pub qtype: Rtype,
    pub client_serial: Option<u32>,
    pub query_id: u16,
    pub opcode: Opcode,
}

impl ParsedQuery {
    /// Parse a DNS question and its optional IXFR serial.
    pub fn parse(data: &[u8]) -> Result<ParsedQuery, String> {
        let message = Message::from_octets(data)
            .map_err(|e| format!("Failed to parse DNS message: {}", e))?;

        let query_id = message.header().id();
        let opcode = message.header().opcode();

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
            opcode,
        })
    }

    /// An empty authoritative answer with TC set, so a transfer client asks
    /// again over TCP (RFC 1995, Section 2; RFC 5936, Section 4.1.1).
    pub fn truncated_response(&self) -> Vec<u8> {
        self.build_question_response(|header| {
            header.set_aa(true);
            header.set_tc(true);
        })
        .finish()
    }

    /// A response echoing this query with only `rcode` set.
    pub fn error_response(&self, rcode: Rcode) -> Vec<u8> {
        self.build_question_response(|header| header.set_rcode(rcode))
            .finish()
    }

    /// The truncated answer, signed when the question was.
    pub fn signed_truncated_response(
        &self,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, String> {
        let question = self.build_question_response(|header| {
            header.set_aa(true);
            header.set_tc(true);
        });
        let Some(signer) = signer else {
            return Ok(question.finish());
        };
        let mut additional = question.additional();
        signer
            .answer(&mut additional, Time48::now())
            .map_err(|e| format!("Failed to sign the response: {}", e))?;
        Ok(additional.finish())
    }

    /// The same, signed by the key that signed the request: an accepted key
    /// answers under itself, error or not (RFC 8945, Section 5.3).
    pub fn signed_error_response(
        &self,
        rcode: Rcode,
        signer: &mut TransferSigner,
    ) -> Result<Vec<u8>, String> {
        let question = self.build_question_response(|header| header.set_rcode(rcode));
        let mut additional = question.additional();
        signer
            .answer(&mut additional, Time48::now())
            .map_err(|e| format!("Failed to sign the response: {}", e))?;
        Ok(additional.finish())
    }

    /// Build a response carrying only this query's question, its header
    /// shaped by `set` after the id and QR.
    fn build_question_response(&self, set: impl FnOnce(&mut Header)) -> QuestionBuilder<Vec<u8>> {
        let mut builder = MessageBuilder::new_vec();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);
        // RFC 1035, Section 4.1.1: a response echoes the request's opcode.
        header.set_opcode(self.opcode);
        set(header);

        let mut question = builder.question();
        question
            .push((&self.qname, self.qtype))
            .expect("composing into a Vec cannot run out of space");

        question
    }
}

/// Read the client's serial from the IXFR authority SOA.
fn extract_ixfr_serial(message: &Message<&[u8]>) -> Option<u32> {
    message
        .authority()
        .ok()?
        .limit_to::<Soa<_>>()
        .find_map(|rr| rr.ok())
        .map(|rr| rr.data().serial().into_int())
}
