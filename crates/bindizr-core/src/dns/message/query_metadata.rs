//! Error and truncated replies, including requests without a readable question.

use domain::base::iana::{Opcode, OptRcode, Rtype};
use domain::base::message_builder::{AdditionalBuilder, TreeCompressor};
use domain::base::{Message, Question};
use domain::rdata::tsig::Time48;

use crate::dns::message;
use crate::dns::message::{
    Edns, EncodeMessageError, ExtendedErrorCode, Keepalive, ParseQueryError, ParsedQuery,
    ResponseLimit,
};
use crate::dns::name::WireName;
use crate::dns::tsig::TransferSigner;

/// Readable request metadata for an error response, with or without a question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMetadata {
    query_id: u16,
    opcode: Opcode,
    rd: bool,
    question: Option<Question<WireName>>,
    edns: Edns,
    keepalive: Keepalive,
}

impl QueryMetadata {
    /// Retain optional sections only when the message uses readable DNS framing.
    pub fn parse(query_data: &[u8], keepalive: Keepalive) -> Result<Self, ParseQueryError> {
        let message = Message::from_octets(query_data)
            .map_err(|error| ParseQueryError::Malformed(Box::new(error)))?;
        Ok(Self::from_message(&message, keepalive))
    }

    /// Retain response metadata from sections with readable DNS framing.
    pub(crate) fn from_message(message: &Message<&[u8]>, keepalive: Keepalive) -> Self {
        use domain::base::ToName;

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

    /// Return the EDNS error alone: FORMERR for a malformed OPT, BADVERS for
    /// an unsupported version (RFC 6891, Sections 6.1.1 and 6.1.3).
    pub fn format_error(&self) -> Option<OptRcode> {
        self.edns.format_error()
    }

    /// Return the negotiated transport budget for the final send.
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
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        let limit = self.response_limit();
        // Signed on a copy of the chain, which is committed only once a message fits.
        let build = |minimal: bool| -> Result<_, EncodeMessageError> {
            let mut candidate_signer = signer.as_deref().cloned();
            let mut additional = self.build_response(
                if minimal {
                    OptRcode::NOERROR
                } else {
                    rcode
                },
                truncated || minimal,
                if minimal {
                    None
                } else {
                    ede
                },
            );

            if let Some(candidate) = &mut candidate_signer {
                candidate
                    .sign_response(&mut additional, Time48::now())
                    .map_err(|error| EncodeMessageError::Sign(Box::new(error)))?;
            }

            Ok((additional.finish().into_target(), candidate_signer))
        };

        let (mut response, mut candidate_signer) = build(false)?;

        // A UDP overflow is answered NOERROR with TC; a stream overflow is an error.
        if let Err(error) = limit.validate_len(response.len()) {
            if !limit.is_udp() {
                return Err(error);
            }

            (response, candidate_signer) = build(true)?;
            limit.validate_len(response.len())?;
        }

        if let (Some(signer), Some(candidate)) = (signer, candidate_signer) {
            *signer = candidate;
        }

        Ok(response)
    }

    /// Build a question-only response with EDNS, ready for optional TSIG signing.
    fn build_response(
        &self,
        rcode: OptRcode,
        truncated: bool,
        ede: Option<ExtendedErrorCode>,
    ) -> AdditionalBuilder<TreeCompressor<Vec<u8>>> {
        let mut builder = message::build_response();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);

        // RFC 1035, Section 4.1.1: a response echoes the request's opcode and RD.
        header.set_opcode(self.opcode);
        header.set_rd(self.rd);
        header.set_rcode(rcode.rcode());

        // RFC 5936, Section 2.2.1: AA stays set on an error about a held zone and
        // "if in doubt"; NOTAUTH, FORMERR and NOTIMP deny authority, so it clears.
        // Only an SOA or transfer question names a zone this server may hold: a
        // refusal of any other question claims no authority (RFC 1035, Section 4.1.1).
        let about_held_zone = self.opcode == Opcode::QUERY
            && self.question.as_ref().is_some_and(|question| {
                matches!(question.qtype(), Rtype::SOA | Rtype::AXFR | Rtype::IXFR)
            });
        header.set_aa(
            self.question.is_some()
                && (truncated
                    || about_held_zone && matches!(rcode, OptRcode::REFUSED | OptRcode::SERVFAIL)),
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

/// Return whether generic DNS section boundaries are usable for EDNS and TSIG parsing.
pub fn has_readable_sections(query_data: &[u8]) -> bool {
    let Ok(message) = Message::from_octets(query_data) else {
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

    additional.pos() == query_data.len()
}
