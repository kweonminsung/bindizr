//! DNS wire-format encoding for zone-transfer responses: message framing and
//! record/SOA serialization.

pub use domain::base::{
    Name,
    iana::{Class, Opcode, Rcode, Rtype},
};
use domain::{
    base::{
        MessageBuilder, ToName, Ttl, UnknownRecordData, rdata::ComposeRecordData,
        record::ComposeRecord, wire::Composer,
    },
    rdata::tsig::Time48,
};

use crate::dns::{
    DNS_TCP_MAX_SIZE,
    dnssec::to_wire_name,
    name::ParseNameError,
    record::Rdata,
    tsig::{TransferSigner, signature_len},
};

/// A size failure that may still carry a frame: the caller must send it so
/// its message count reflects what reached the client before the failure.
pub struct Overflow {
    /// The answers buffered before the oversized one, if there were any.
    pub frame: Option<Vec<u8>>,
    pub message: String,
}

impl Overflow {
    /// Build an overflow error without a pending TCP frame.
    fn without_frame(message: String) -> Self {
        Overflow {
            frame: None,
            message,
        }
    }
}

/// What [`DnsMessageBuilder::add_raw_rdata`] accepts as its owner: a parsed
/// name, or a typed name's wire bytes still carrying their encoding error.
pub trait IntoOwner {
    /// Convert an accepted owner representation into a wire-format name.
    fn into_owner(self) -> Result<Name<Vec<u8>>, String>;
}

impl IntoOwner for Name<Vec<u8>> {
    /// Convert an accepted owner representation into a wire-format name.
    fn into_owner(self) -> Result<Name<Vec<u8>>, String> {
        Ok(self)
    }
}

impl IntoOwner for Result<Vec<u8>, ParseNameError> {
    /// Convert an accepted owner representation into a wire-format name.
    fn into_owner(self) -> Result<Name<Vec<u8>>, String> {
        to_wire_name(self)
    }
}

/// An RR already composed into wire bytes, pushed back through `domain`'s
/// builder so a message can carry a section it did not compose.
struct ComposedRr<'a>(&'a [u8]);

impl ComposeRecord for ComposedRr<'_> {
    /// Append the precomposed record bytes to the message.
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.0)
    }
}

pub struct DnsMessageBuilder {
    query_id: u16,
    qname: Name<Vec<u8>>,
    qtype: u16,
    answers: Vec<Vec<u8>>,
    /// Total byte length of `answers`, maintained incrementally for `message_len`.
    answers_len: usize,
    /// Signs every message this builder produces, carrying one MAC chain
    /// across the envelopes of a transfer.
    signer: Option<TransferSigner>,
}

impl DnsMessageBuilder {
    /// Create a DNS response builder for the supplied question.
    pub fn new(query_id: u16, qname: &Name<Vec<u8>>, qtype: Rtype) -> Self {
        Self {
            query_id,
            qname: qname.clone(),
            qtype: qtype.to_int(),
            answers: Vec::new(),
            answers_len: 0,
            signer: None,
        }
    }

    /// Sign what this builder produces, for a request that arrived signed. The
    /// TSIG record's own bytes count against the message size limit.
    pub fn sign_with(mut self, signer: TransferSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Hand the signer back to a caller answering the request another way.
    /// Only sound before the first frame: a MAC chain cannot be rewound.
    pub fn take_signer(&mut self) -> Option<TransferSigner> {
        self.signer.take()
    }

    /// Adds an answer from wire-format RDATA bytes, with no per-type parser.
    pub(crate) fn add_raw_rdata(
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
        let rr = domain::base::Record::new(owner, Class::IN, Ttl::from_secs(ttl), data);
        let mut answer = Vec::new();
        rr.compose_record(&mut answer)
            .expect("composing into a Vec cannot run out of space");
        self.push_answer(answer);
    }

    /// Return the number of buffered answers.
    fn answer_count(&self) -> usize {
        self.answers.len()
    }

    /// Calculate the response size including the question and optional TSIG.
    fn message_len(&self) -> usize {
        let signature = self.signer.as_ref().map_or(0, signature_len);
        12 + self.qname.len() + 4 + self.answers_len + signature
    }

    /// Remove the last answer and update the buffered byte count.
    fn pop_last_answer(&mut self) -> Option<Vec<u8>> {
        let answer = self.answers.pop();
        if let Some(answer) = &answer {
            self.answers_len -= answer.len();
        }
        answer
    }

    /// Buffer an answer and update the buffered byte count.
    fn push_answer(&mut self, answer: Vec<u8>) {
        self.answers_len += answer.len();
        self.answers.push(answer);
    }

    /// Clear the answers and reset the buffered byte count.
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

        // Keep the overflowing answer out of the frame built from earlier answers.
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

    /// Describe the buffered answer that exceeds the DNS message limit.
    fn too_large_message(&self) -> String {
        format!(
            "Single DNS answer is too large: {} bytes",
            self.message_len()
        )
    }

    /// Compose the buffered answers into one authoritative response, signed
    /// when the request was. Built through `domain`, which composes the
    /// additional section a TSIG record needs.
    fn build_message(&mut self) -> Result<Vec<u8>, String> {
        let mut builder = MessageBuilder::new_vec();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);
        header.set_aa(true);

        let mut question = builder.question();
        question
            .push((&self.qname, Rtype::from_int(self.qtype), Class::IN))
            .map_err(|e| format!("Failed to compose the question: {}", e))?;

        let mut answer = question.answer();
        for composed in &self.answers {
            answer
                .push(ComposedRr(composed))
                .map_err(|e| format!("Failed to compose an answer: {}", e))?;
        }

        let mut additional = answer.additional();
        if let Some(signer) = self.signer.as_mut() {
            signer
                .answer(&mut additional, Time48::now())
                .map_err(|e| format!("Failed to sign the response: {}", e))?;
        }
        Ok(additional.finish())
    }

    /// Serializes into a length-prefixed TCP frame.
    fn build_tcp_frame(&mut self) -> Result<Vec<u8>, String> {
        let message = self.build_message()?;
        encode_tcp_message(&message)
    }

    /// Consume the builder and serialize its DNS response.
    pub fn build(mut self) -> Result<Vec<u8>, String> {
        self.build_message()
    }
}

/// Prefix a DNS message with its two-byte TCP frame length.
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

mod query;
mod records;

pub use query::{ParsedQuery, is_response};

#[cfg(test)]
mod tests;
