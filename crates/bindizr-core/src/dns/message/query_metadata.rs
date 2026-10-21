//! Error and truncated replies, including requests without a readable question.

use domain::{
    base::{
        Message, Name, Question, ToName,
        iana::{Opcode, OptRcode},
        message_builder::{AdditionalBuilder, TreeCompressor},
    },
    rdata::tsig::Time48,
};

use super::{
    Edns, EncodeMessageError, ExtendedErrorCode, Keepalive, ParseQueryError, ParsedQuery,
    ResponseLimit,
};
use crate::dns::tsig::TransferSigner;

/// Readable request metadata for an error response, with or without a question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMetadata {
    query_id: u16,
    opcode: Opcode,
    rd: bool,
    question: Option<Question<Name<Vec<u8>>>>,
    edns: Edns,
    keepalive: Keepalive,
}

impl QueryMetadata {
    /// Retain optional sections only when the message uses readable DNS framing.
    pub fn parse(data: &[u8], keepalive: Keepalive) -> Result<Self, ParseQueryError> {
        let message = Message::from_octets(data)
            .map_err(|error| ParseQueryError::Malformed(Box::new(error)))?;
        Ok(Self::from_message(&message, keepalive))
    }

    /// Retain response metadata from sections with readable DNS framing.
    pub(crate) fn from_message(message: &Message<&[u8]>, keepalive: Keepalive) -> Self {
        let readable = has_readable_sections(message.as_slice());
        Self {
            query_id: message.header().id(),
            opcode: message.header().opcode(),
            rd: message.header().rd(),
            question: if readable {
                message.first_question().map(|question| {
                    Question::new(
                        question.qname().to_name::<Vec<u8>>(),
                        question.qtype(),
                        question.qclass(),
                    )
                })
            } else {
                None
            },
            edns: if readable {
                Edns::from_message(message)
            } else {
                Edns::Absent
            },
            keepalive,
        }
    }

    /// An EDNS error takes precedence over the default questionless refusal.
    pub fn format_error(&self) -> Option<OptRcode> {
        self.edns.format_error()
    }

    /// Carry the negotiated transport budget into the final send.
    pub fn response_limit(&self) -> ResponseLimit {
        self.keepalive.response_limit(self.edns)
    }

    /// Sign an error under the accepted key, including questionless requests.
    pub fn build_signed_error_response(
        &self,
        rcode: OptRcode,
        ede: Option<ExtendedErrorCode>,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        self.build_signed_response(rcode, false, ede, signer)
    }

    /// Build a bounded TC response with the request's optional signature.
    pub(crate) fn build_signed_truncated_response(
        &self,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        self.build_signed_response(OptRcode::NOERROR, true, None, signer)
    }

    /// Sign a bounded response, rebuilding with TC on overflow.
    fn build_signed_response(
        &self,
        rcode: OptRcode,
        truncated: bool,
        ede: Option<ExtendedErrorCode>,
        mut signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        let limit = self.response_limit();

        for minimal in [false, true] {
            let mut candidate_signer = signer.as_deref().cloned();
            let mut additional = self.build_response(
                if minimal { OptRcode::NOERROR } else { rcode },
                truncated || minimal,
                if minimal { None } else { ede },
            );

            if let Some(candidate) = &mut candidate_signer {
                candidate
                    .sign_response(&mut additional, Time48::now())
                    .map_err(|error| EncodeMessageError::Sign(Box::new(error)))?;
            }

            let response = additional.finish().into_target();

            match limit.validate_len(response.len()) {
                Ok(()) => {
                    if let (Some(signer), Some(candidate)) =
                        (signer.as_deref_mut(), candidate_signer)
                    {
                        *signer = candidate;
                    }
                    return Ok(response);
                }
                Err(error) if minimal || !limit.is_udp() => return Err(error),
                Err(_) => {}
            }
        }

        unreachable!()
    }

    /// Build a question-only response with EDNS, ready for optional TSIG signing.
    fn build_response(
        &self,
        rcode: OptRcode,
        truncated: bool,
        ede: Option<ExtendedErrorCode>,
    ) -> AdditionalBuilder<TreeCompressor<Vec<u8>>> {
        let mut builder = super::build_response();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);

        // RFC 1035, Section 4.1.1: a response echoes the request's opcode and RD.
        header.set_opcode(self.opcode);
        header.set_rd(self.rd);
        header.set_rcode(rcode.rcode());

        // RFC 5936, Section 2.2.1: AA stays set on an error about a held zone and
        // "if in doubt"; NOTAUTH, FORMERR and NOTIMP deny authority, so it clears.
        header.set_aa(
            self.question.is_some()
                && (truncated || matches!(rcode, OptRcode::REFUSED | OptRcode::SERVFAIL)),
        );
        header.set_tc(truncated);

        let mut question = builder.question();

        if let Some(value) = &self.question {
            question
                .push(value)
                .expect("one question fits an unlimited message");
        }

        let mut additional = question.additional();
        self.edns
            .push_response_opt(&mut additional, rcode, ede, self.keepalive.tcp_keepalive());

        additional
    }
}

impl From<&ParsedQuery> for QueryMetadata {
    /// Copy the parsed query's response metadata without its record sections.
    fn from(query: &ParsedQuery) -> Self {
        Self {
            query_id: query.query_id,
            opcode: query.opcode,
            rd: query.rd,
            question: Some(Question::new(
                query.qname.clone(),
                query.qtype,
                query.qclass,
            )),
            edns: query.edns,
            keepalive: query.keepalive,
        }
    }
}

/// Whether generic DNS section boundaries are usable for EDNS and TSIG parsing.
pub fn has_readable_sections(data: &[u8]) -> bool {
    let Ok(message) = Message::from_octets(data) else {
        return false;
    };
    let Ok(mut additional) = message.additional() else {
        return false;
    };

    for record in additional.by_ref() {
        if record.is_err() {
            return false;
        }
    }

    additional.pos() == data.len()
}
