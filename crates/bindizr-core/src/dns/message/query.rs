//! Reading an inbound query: what the listener parses once and hands to every
//! handler, and the short replies it answers without touching the zone.

use std::time::Duration;

pub use domain::base::iana::exterr::ExtendedErrorCode;
use domain::{
    base::{
        Message, MessageBuilder, Name, Rtype, ToName,
        iana::{Class, Opcode, OptRcode, Rcode},
        message_builder::{AdditionalBuilder, TreeCompressor},
        opt::{
            Opt, OptRecord,
            exterr::ExtendedError,
            keepalive::{IdleTimeout, TcpKeepalive},
        },
        wire::Composer,
    },
    rdata::{Soa, tsig::Time48},
};
use thiserror::Error;

use super::{EncodeMessageError, RECORD_FIELDS_LEN, ResponseLimit};
use crate::dns::{LibraryError, query::EDNS_UDP_PAYLOAD_SIZE, tsig::TransferSigner};

/// A UDP answer to a query without EDNS is at most 512 octets (RFC 1035,
/// Section 4.2.1).
pub const UDP_PAYLOAD_SIZE_WITHOUT_EDNS: u16 = 512;

/// The wire size of the OPT record a response carries, options aside.
pub(crate) const OPT_RECORD_LEN: usize = 1 + RECORD_FIELDS_LEN;

/// The wire size of the edns-tcp-keepalive option with its timeout.
pub(crate) const KEEPALIVE_OPTION_LEN: usize = 6;

/// What the query said through its OPT record (RFC 6891), or what it got
/// wrong; a query that carried one is answered with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edns {
    Absent,
    /// One readable OPT; sizes under 512 read as 512 (Section 6.2.3).
    Present {
        udp_payload_size: u16,
        version: u8,
        dnssec_ok: bool,
    },
    /// More than one OPT, or one that does not parse: FORMERR (Section 6.1.1).
    Malformed,
}

impl Edns {
    /// Whether the requester asks for DNSSEC records (RFC 3225).
    pub fn dnssec_ok(self) -> bool {
        matches!(
            self,
            Self::Present {
                dnssec_ok: true,
                ..
            }
        )
    }

    /// Read the request's OPT metadata, retaining flags even for unsupported versions.
    pub(crate) fn from_message(message: &Message<&[u8]>) -> Self {
        // RFC 6891, Section 6.1.1: OPT belongs only in Additional, once per message.
        for section in [message.answer(), message.authority()] {
            let Ok(section) = section else {
                return Self::Malformed;
            };
            for record in section {
                if !record.is_ok_and(|record| record.rtype() != Rtype::OPT) {
                    return Self::Malformed;
                }
            }
        }
        let Ok(additional) = message.additional() else {
            return Self::Malformed;
        };
        let mut opts = additional.limit_to::<Opt<_>>();
        let first = match opts.next() {
            None => return Self::Absent,
            Some(Err(_)) => return Self::Malformed,
            Some(Ok(record)) => {
                if !record.owner().is_root() {
                    return Self::Malformed;
                }
                OptRecord::from(record)
            }
        };
        if opts.next().is_some() {
            return Self::Malformed;
        }
        Self::Present {
            udp_payload_size: first.udp_payload_size().max(UDP_PAYLOAD_SIZE_WITHOUT_EDNS),
            version: first.version(),
            dnssec_ok: first.dnssec_ok(),
        }
    }

    /// Return FORMERR or BADVERS for unacceptable EDNS (RFC 6891, Sections 6.1.1 and 6.1.3).
    pub fn format_error(self) -> Option<OptRcode> {
        match self {
            Self::Absent | Self::Present { version: 0, .. } => None,
            Self::Malformed => Some(OptRcode::FORMERR),
            Self::Present { .. } => Some(OptRcode::BADVERS),
        }
    }

    /// Append response EDNS metadata and options when requested (RFC 6891, Section 6.1.1).
    pub(crate) fn push_response<Target: Composer>(
        self,
        additional: &mut AdditionalBuilder<Target>,
        rcode: OptRcode,
        ede: Option<ExtendedErrorCode>,
        keepalive: Option<TcpKeepalive>,
    ) {
        if self == Self::Absent {
            return;
        }
        additional
            .opt(|opt| {
                opt.set_udp_payload_size(EDNS_UDP_PAYLOAD_SIZE);
                opt.set_rcode(rcode);
                // RFC 3225, Section 3: copy DO, leaving reserved flags clear.
                opt.set_dnssec_ok(matches!(
                    self,
                    Self::Present {
                        dnssec_ok: true,
                        ..
                    }
                ));
                if let Some(code) = ede {
                    opt.push(&ExtendedError::<Vec<u8>>::from(code))?;
                }
                if let Some(keepalive) = keepalive {
                    opt.push(&keepalive)?;
                }
                Ok(())
            })
            .expect("one OPT record fits an unlimited message");
    }
}

/// What the listener advertises about the connection: nothing for a
/// datagram, the idle timeout for a connection (RFC 7828, Section 3.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keepalive {
    None,
    IdleTimeout(Duration),
}

/// An inbound message the listener could not read as a query.
#[derive(Debug, Error)]
pub enum ParseQueryError {
    #[error("failed to parse DNS message: {0}")]
    Malformed(#[source] LibraryError),
    #[error("no question in DNS query")]
    NoQuestion {
        query_id: u16,
        opcode: Opcode,
        rd: bool,
        question_count: u16,
    },
}

impl ParseQueryError {
    /// Build a header-only FORMERR for a message with no readable question:
    /// none, an unparsable one, or more than one for QUERY (RFC 9619, Section 4).
    pub fn to_response(&self) -> Option<Vec<u8>> {
        let Self::NoQuestion {
            query_id,
            opcode,
            rd,
            ..
        } = self
        else {
            return None;
        };
        let mut builder = MessageBuilder::new_vec();
        let header = builder.header_mut();
        header.set_id(*query_id);
        header.set_qr(true);
        header.set_opcode(*opcode);
        header.set_rd(*rd);
        header.set_rcode(Rcode::FORMERR);
        Some(builder.question().finish())
    }
}

/// Reject QUERY question counts other than one (RFC 9619, Section 4).
fn question_count_error(opcode: Opcode, count: u16) -> Option<OptRcode> {
    (opcode == Opcode::QUERY && count != 1).then_some(OptRcode::FORMERR)
}

/// Whether the message is itself a response (QR=1). Answering one lets a
/// spoofed source aim the reply at a third party.
pub fn is_response(message: &[u8]) -> bool {
    Message::from_octets(message).is_ok_and(|message| message.header().qr())
}

/// A DNS query parsed once at the listener and handed to every handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuery {
    pub qname: Name<Vec<u8>>,
    /// Presentation form of `qname` without the trailing dot.
    pub zone_name: String,
    pub qtype: Rtype,
    /// Echoed in every response (RFC 5936, Section 2.2.2); only IN is served.
    pub qclass: Class,
    pub question_count: u16,
    pub client_serial: Option<u32>,
    pub query_id: u16,
    pub opcode: Opcode,
    /// Copied into every response (RFC 1035, Section 4.1.1).
    pub rd: bool,
    pub edns: Edns,
    /// What the listener advertises about the connection.
    pub keepalive: Keepalive,
}

impl ParsedQuery {
    /// Parse a DNS question and its optional IXFR serial.
    pub fn parse(data: &[u8], keepalive: Keepalive) -> Result<ParsedQuery, ParseQueryError> {
        let message =
            Message::from_octets(data).map_err(|e| ParseQueryError::Malformed(Box::new(e)))?;

        let query_id = message.header().id();
        let opcode = message.header().opcode();
        let rd = message.header().rd();
        let edns = Edns::from_message(&message);

        let question = message
            .first_question()
            .ok_or(ParseQueryError::NoQuestion {
                query_id,
                opcode,
                rd,
                question_count: message.header_counts().qdcount(),
            })?;

        let qname = question.qname().to_name::<Vec<u8>>();
        let qtype = question.qtype();
        let qclass = question.qclass();

        // Only the root maps to an empty zone name; escaped label dots stay data.
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
            qclass,
            question_count: message.header_counts().qdcount(),
            client_serial,
            query_id,
            opcode,
            rd,
            edns,
            keepalive,
        })
    }

    /// Advertise the TCP idle timeout (RFC 7828, Section 3.3.2); none over UDP.
    pub(crate) fn tcp_keepalive(&self) -> Option<TcpKeepalive> {
        let Keepalive::IdleTimeout(idle_timeout) = self.keepalive else {
            return None;
        };
        let Ok(timeout) = IdleTimeout::try_from(idle_timeout) else {
            return None;
        };
        Some(TcpKeepalive::new(Some(timeout)))
    }

    /// Use the request's transport and EDNS advertisement for every response encoder.
    pub fn response_limit(&self) -> ResponseLimit {
        match self.keepalive {
            Keepalive::IdleTimeout(_) => ResponseLimit::STREAM,
            Keepalive::None => match self.edns {
                Edns::Present {
                    udp_payload_size, ..
                } => ResponseLimit::udp(udp_payload_size),
                _ => ResponseLimit::UDP,
            },
        }
    }

    /// The response code for an invalid question count or EDNS record.
    pub fn format_error(&self) -> Option<OptRcode> {
        if let Some(rcode) = question_count_error(self.opcode, self.question_count) {
            return Some(rcode);
        }
        self.edns.format_error()
    }

    /// The truncated answer, signed when the question was.
    pub fn build_signed_truncated_response(
        &self,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        self.finish_signed_response(OptRcode::NOERROR, true, None, signer)
    }

    /// The error response, signed when a key was accepted: an accepted key
    /// answers under itself, error or not (RFC 8945, Section 5.3).
    pub fn build_signed_error_response(
        &self,
        rcode: OptRcode,
        ede: Option<ExtendedErrorCode>,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        self.finish_signed_response(rcode, false, ede, signer)
    }

    /// Sign a bounded response, rebuilding with TC on overflow.
    fn finish_signed_response(
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
                    .map_err(|e| EncodeMessageError::Sign(Box::new(e)))?;
            }
            let response = additional.finish().into_target();
            match limit.check_len(response.len()) {
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
        header.set_aa(truncated || matches!(rcode, OptRcode::REFUSED | OptRcode::SERVFAIL));
        header.set_tc(truncated);

        let mut question = builder.question();
        question
            .push((&self.qname, self.qtype, self.qclass))
            .expect("one question fits an unlimited message");

        let mut additional = question.additional();
        self.edns
            .push_response(&mut additional, rcode, ede, self.tcp_keepalive());
        additional
    }
}

/// Read the client's serial from the IXFR authority SOA.
fn extract_ixfr_serial(message: &Message<&[u8]>) -> Option<u32> {
    message
        .authority()
        .ok()?
        .limit_to::<Soa<_>>()
        .find_map(|record| record.ok())
        .map(|record| record.data().serial().into_int())
}
