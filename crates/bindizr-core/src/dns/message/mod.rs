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
use thiserror::Error;

use crate::dns::{
    ConvertSerialError, DNS_TCP_MAX_SIZE, LibraryError,
    dnssec::WireNameError,
    name::EncodeNameError,
    record::{EncodeRdataError, Rdata},
    tsig::{TransferSigner, signature_len},
};

/// Why a response could not be composed, signed, or framed.
#[derive(Debug, Error)]
pub enum EncodeMessageError {
    #[error("Invalid raw rdata: {0}")]
    RawRdata(#[source] LibraryError),
    #[error(transparent)]
    Owner(#[from] WireNameError),
    #[error(transparent)]
    Name(#[from] EncodeNameError),
    #[error(transparent)]
    Rdata(#[from] EncodeRdataError),
    #[error(transparent)]
    Serial(#[from] ConvertSerialError),
    #[error("derived change carries no wire rdata")]
    MissingRdata,
    #[error("user change carries no record value")]
    MissingValue,
    #[error("DNS message exceeded maximum size without answers")]
    NoAnswers,
    #[error("Single DNS answer is too large: {len} bytes")]
    AnswerTooLarge { len: usize },
    #[error("Message too large: {len} bytes")]
    TooLarge { len: usize },
    #[error("Failed to compose the question: {0}")]
    ComposeQuestion(#[source] LibraryError),
    #[error("Failed to compose an answer: {0}")]
    ComposeAnswer(#[source] LibraryError),
    #[error("Failed to sign the response: {0}")]
    Sign(#[source] LibraryError),
}

/// A size failure that may still carry a frame: the caller must send it so
/// its message count reflects what reached the client before the failure.
#[derive(Debug, Error)]
#[error("{source}")]
pub struct Overflow {
    /// The answers buffered before the oversized one, if there were any.
    pub frame: Option<Vec<u8>>,
    #[source]
    pub source: EncodeMessageError,
}

impl Overflow {
    /// Build an overflow error without a pending TCP frame.
    fn without_frame(source: EncodeMessageError) -> Self {
        Overflow {
            frame: None,
            source,
        }
    }
}

/// A record already composed into wire bytes, pushed back through `domain`'s
/// builder so a message can carry a section it did not compose.
struct ComposedRecord<'a>(&'a [u8]);

impl ComposeRecord for ComposedRecord<'_> {
    /// Append the precomposed record bytes to the message.
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.0)
    }
}

#[derive(Debug)]
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
        owner: Name<Vec<u8>>,
        record_type: u16,
        ttl: u32,
        rdata: Rdata,
    ) -> Result<(), EncodeMessageError> {
        let data = UnknownRecordData::from_octets(Rtype::from_int(record_type), rdata.into_bytes())
            .map_err(|e| EncodeMessageError::RawRdata(Box::new(e)))?;
        self.add_answer(owner, ttl, data);
        Ok(())
    }

    /// Composes one class-IN answer record into its own buffer so it can be
    /// popped/reflushed by the chunked TCP writer.
    fn add_answer<N: ToName, D: ComposeRecordData>(&mut self, owner: N, ttl: u32, data: D) {
        let record = domain::base::Record::new(owner, Class::IN, Ttl::from_secs(ttl), data);
        let mut answer = Vec::new();
        let Ok(()) = record.compose_record(&mut answer);
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
        F: FnOnce(&mut DnsMessageBuilder) -> Result<(), EncodeMessageError>,
    {
        add_answer(self).map_err(Overflow::without_frame)?;

        if self.message_len() <= DNS_TCP_MAX_SIZE {
            return Ok(None);
        }

        // Keep the overflowing answer out of the frame built from earlier answers.
        let last_answer = self
            .pop_last_answer()
            .ok_or_else(|| Overflow::without_frame(EncodeMessageError::NoAnswers))?;

        if self.answer_count() == 0 {
            self.push_answer(last_answer);
            return Err(Overflow::without_frame(self.answer_too_large()));
        }

        let frame = self.take_frame().map_err(Overflow::without_frame)?;

        self.push_answer(last_answer);
        if self.message_len() > DNS_TCP_MAX_SIZE {
            return Err(Overflow {
                frame,
                source: self.answer_too_large(),
            });
        }

        Ok(frame)
    }

    /// The buffered answers as a length-prefixed TCP frame, clearing them;
    /// `None` when nothing is buffered.
    pub fn take_frame(&mut self) -> Result<Option<Vec<u8>>, EncodeMessageError> {
        if self.answer_count() == 0 {
            return Ok(None);
        }
        let frame = self.build_tcp_frame()?;
        self.clear_answers();
        Ok(Some(frame))
    }

    /// The error for a buffered answer that exceeds the DNS message limit.
    fn answer_too_large(&self) -> EncodeMessageError {
        EncodeMessageError::AnswerTooLarge {
            len: self.message_len(),
        }
    }

    /// Compose the buffered answers into one authoritative response, signed
    /// when the request was. Built through `domain`, which composes the
    /// additional section a TSIG record needs.
    fn build_message(&mut self) -> Result<Vec<u8>, EncodeMessageError> {
        let mut builder = MessageBuilder::new_vec();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);
        header.set_aa(true);

        let mut question = builder.question();
        question
            .push((&self.qname, Rtype::from_int(self.qtype), Class::IN))
            .map_err(|e| EncodeMessageError::ComposeQuestion(Box::new(e)))?;

        let mut answer = question.answer();
        for composed in &self.answers {
            answer
                .push(ComposedRecord(composed))
                .map_err(|e| EncodeMessageError::ComposeAnswer(Box::new(e)))?;
        }

        let mut additional = answer.additional();
        if let Some(signer) = self.signer.as_mut() {
            signer
                .answer(&mut additional, Time48::now())
                .map_err(|e| EncodeMessageError::Sign(Box::new(e)))?;
        }
        Ok(additional.finish())
    }

    /// Serializes into a length-prefixed TCP frame.
    fn build_tcp_frame(&mut self) -> Result<Vec<u8>, EncodeMessageError> {
        let message = self.build_message()?;
        encode_tcp_message(&message)
    }

    /// Consume the builder and serialize its DNS response.
    pub fn build(mut self) -> Result<Vec<u8>, EncodeMessageError> {
        self.build_message()
    }
}

/// Prefix a DNS message with its two-byte TCP frame length.
pub fn encode_tcp_message(message: &[u8]) -> Result<Vec<u8>, EncodeMessageError> {
    if message.len() > DNS_TCP_MAX_SIZE {
        return Err(EncodeMessageError::TooLarge { len: message.len() });
    }

    let len = message.len() as u16;
    let mut result = Vec::with_capacity(2 + message.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(message);
    Ok(result)
}

mod query;
mod records;

pub use query::{ParseQueryError, ParsedQuery, is_response};

#[cfg(test)]
mod tests;
