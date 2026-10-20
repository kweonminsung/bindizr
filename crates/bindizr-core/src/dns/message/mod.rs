//! DNS wire-format encoding for zone-transfer responses: message framing and
//! record/SOA serialization.

pub use domain::base::{
    Name,
    iana::{Class, Opcode, OptRcode, Rcode, Rtype},
};
use domain::{
    base::{
        MessageBuilder, ToName, Ttl, UnknownRecordData, message_builder::TreeCompressor,
        opt::keepalive::TcpKeepalive, rdata::ComposeRecordData, record::ComposeRecord,
        wire::Composer,
    },
    rdata::tsig::Time48,
};
use thiserror::Error;

use crate::dns::{
    ConvertSerialError, LibraryError,
    dnssec::EncodeWireNameError,
    name::EncodeNameError,
    record::{EncodeRdataError, Rdata},
    tsig::{TransferSigner, signature_len},
};

/// Fixed DNS message header length (RFC 1035, Section 4.1.1).
pub(crate) const DNS_HEADER_LEN: usize = 12;

/// QTYPE and QCLASS length, excluding the question name.
pub(crate) const QUESTION_FIELDS_LEN: usize = 4;

/// TYPE, CLASS, TTL and RDLENGTH length, excluding owner name and RDATA.
pub(crate) const RECORD_FIELDS_LEN: usize = 10;

/// Compress response names before signing.
pub(crate) fn build_response() -> MessageBuilder<TreeCompressor<Vec<u8>>> {
    MessageBuilder::from_target(TreeCompressor::new(Vec::new()))
        .expect("a Vec holds the DNS header")
}

/// Why a response could not be composed, signed, or framed.
#[derive(Debug, Error)]
pub enum EncodeMessageError {
    #[error("invalid raw rdata: {0}")]
    RawRdata(#[source] LibraryError),
    #[error(transparent)]
    Owner(#[from] EncodeWireNameError),
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
    #[error("single DNS answer is too large: {len} bytes")]
    AnswerTooLarge { len: usize },
    #[error("message too large: {len} bytes (limit {max_len})")]
    TooLarge { len: usize, max_len: usize },
    #[error("failed to compose the question: {0}")]
    ComposeQuestion(#[source] LibraryError),
    #[error("failed to compose an answer: {0}")]
    ComposeAnswer(#[source] LibraryError),
    #[error("failed to sign the response: {0}")]
    Sign(#[source] LibraryError),
}

/// An answer or encoding failure that may carry a frame to send first.
#[derive(Debug, Error)]
#[error("{source}")]
pub struct AddAnswerError {
    /// The answers buffered before the oversized one, if there were any.
    pub frame: Option<Vec<u8>>,
    #[source]
    pub source: EncodeMessageError,
}

impl AddAnswerError {
    /// Build an answer error without a pending TCP frame.
    fn without_frame(source: EncodeMessageError) -> Self {
        AddAnswerError {
            frame: None,
            source,
        }
    }
}

/// A record already composed into wire bytes, pushed back through `domain`'s
/// builder so a message can carry a section it did not compose.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
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

#[derive(Debug, Clone)]
pub struct DnsMessageBuilder {
    limit: ResponseLimit,
    query_id: u16,
    qname: Name<Vec<u8>>,
    qtype: u16,
    qclass: Class,
    answers: Vec<Vec<u8>>,
    /// Total byte length of `answers`, maintained incrementally for `message_len`.
    answers_len: usize,
    /// Sign every message, chaining MACs across transfer envelopes.
    signer: Option<TransferSigner>,
    /// The query's RD, copied into every message (RFC 1035, Section 4.1.1).
    rd: bool,
    /// Request EDNS metadata, echoed in each frame (RFC 9103, Section 6.3.4).
    edns: Edns,
    /// The keepalive that OPT carries over TCP (RFC 7828, Section 3.3.2).
    keepalive: Option<TcpKeepalive>,
    /// Set once the answers were dropped to fit a UDP limit.
    truncated: bool,
}

impl DnsMessageBuilder {
    /// Create a response builder answering `query` under `qtype`, which an
    /// IXFR falling back to AXFR keeps as asked.
    pub fn new(query: &ParsedQuery, qtype: Rtype) -> Self {
        Self {
            limit: query.response_limit(),
            query_id: query.query_id,
            qname: query.qname.clone(),
            qtype: qtype.to_int(),
            qclass: query.qclass,
            answers: Vec::new(),
            answers_len: 0,
            signer: None,
            rd: query.rd,
            edns: query.edns,
            keepalive: query.tcp_keepalive(),
            truncated: false,
        }
    }

    /// Sign what this builder produces, for a request that arrived signed. The
    /// TSIG record's own bytes count against the message size limit.
    pub fn sign_with(mut self, signer: TransferSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Return the signer for an alternate response, preserving the MAC chain
    /// through errors (RFC 8945, Section 5.3.1).
    pub fn take_signer(&mut self) -> Option<TransferSigner> {
        self.signer.take()
    }

    /// Adds an answer from wire-format RDATA bytes, with no per-type parser.
    pub fn add_raw_rdata(
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

    /// Calculate the response size including the question, the OPT an EDNS
    /// query is owed, and the optional TSIG.
    fn message_len(&self) -> usize {
        let signature = self.signer.as_ref().map_or(0, signature_len);
        let opt = if self.edns != Edns::Absent {
            OPT_RECORD_LEN + self.keepalive.map_or(0, |_| KEEPALIVE_OPTION_LEN)
        } else {
            0
        };
        DNS_HEADER_LEN + self.qname.len() + QUESTION_FIELDS_LEN + self.answers_len + opt + signature
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

    /// Buffer one answer; on overflow, return the preceding answers as a TCP
    /// frame and retain this answer for the next frame.
    pub fn add_answer_or_overflow<F>(
        &mut self,
        add_answer: F,
    ) -> Result<Option<Vec<u8>>, AddAnswerError>
    where
        F: FnOnce(&mut DnsMessageBuilder) -> Result<(), EncodeMessageError>,
    {
        add_answer(self).map_err(AddAnswerError::without_frame)?;

        if self.message_len() <= self.limit.max_len() {
            return Ok(None);
        }

        // Keep the overflowing answer out of the frame built from earlier answers.
        let last_answer = self
            .pop_last_answer()
            .ok_or_else(|| AddAnswerError::without_frame(EncodeMessageError::NoAnswers))?;

        if self.answer_count() == 0 {
            self.push_answer(last_answer);
            return Err(AddAnswerError::without_frame(self.answer_too_large()));
        }

        let frame = self.take_frame().map_err(AddAnswerError::without_frame)?;

        self.push_answer(last_answer);
        if self.message_len() > self.limit.max_len() {
            return Err(AddAnswerError {
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

    /// Compose the buffered answers into an authoritative response, signing when configured.
    fn build_message(&mut self) -> Result<Vec<u8>, EncodeMessageError> {
        let mut builder = build_response();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);
        header.set_aa(true);
        header.set_rd(self.rd);
        header.set_tc(self.truncated);

        let mut question = builder.question();
        question
            .push((&self.qname, Rtype::from_int(self.qtype), self.qclass))
            .map_err(|e| EncodeMessageError::ComposeQuestion(Box::new(e)))?;

        let mut answer = question.answer();
        for composed in &self.answers {
            answer
                .push(ComposedRecord(composed))
                .map_err(|e| EncodeMessageError::ComposeAnswer(Box::new(e)))?;
        }

        // The OPT precedes the TSIG, which must be last (RFC 8945, Section 5.1).
        let mut additional = answer.additional();
        self.edns
            .push_response(&mut additional, OptRcode::NOERROR, None, self.keepalive);
        if let Some(signer) = self.signer.as_mut() {
            signer
                .sign_response(&mut additional, Time48::now())
                .map_err(|e| EncodeMessageError::Sign(Box::new(e)))?;
        }
        Ok(additional.finish().into_target())
    }

    /// Serializes into a length-prefixed TCP frame.
    fn build_tcp_frame(&mut self) -> Result<Vec<u8>, EncodeMessageError> {
        let signer = self.signer.clone();
        let frame = self.build_message().and_then(|message| {
            self.limit.check_len(message.len())?;
            encode_tcp_message(&message)
        });
        if frame.is_err() {
            self.signer = signer;
        }
        frame
    }

    /// Build within the query's response budget: UDP overflow drops answers
    /// and TC set (RFC 6891, Section 7 keeps the header, question, and OPT).
    pub fn build(mut self) -> Result<Vec<u8>, EncodeMessageError> {
        let signer = self.signer.clone();
        let response = self.build_message()?;
        if let Err(error) = self.limit.check_len(response.len()) {
            if !self.limit.is_udp() {
                return Err(error);
            }
            // Rebuild from the original MAC chain (RFC 8945, Section 5.3).
            self.signer = signer;
            self.clear_answers();
            self.truncated = true;
            let response = self.build_message()?;
            self.limit.check_len(response.len())?;
            return Ok(response);
        }
        Ok(response)
    }
}

/// Prefix a DNS message with its two-byte TCP frame length.
pub fn encode_tcp_message(message: &[u8]) -> Result<Vec<u8>, EncodeMessageError> {
    ResponseLimit::STREAM.check_len(message.len())?;

    let len = message.len() as u16;
    let mut result = Vec::with_capacity(2 + message.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(message);
    Ok(result)
}

mod limit;
pub(crate) mod query;
mod records;

pub use limit::ResponseLimit;
pub use query::{
    Edns, ExtendedErrorCode, Keepalive, ParseQueryError, ParsedQuery,
    UDP_PAYLOAD_SIZE_WITHOUT_EDNS, is_response,
};
use query::{KEEPALIVE_OPTION_LEN, OPT_RECORD_LEN};

#[cfg(test)]
mod tests;
