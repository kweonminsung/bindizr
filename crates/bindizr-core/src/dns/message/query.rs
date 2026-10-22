//! DNS query parsing, response metadata, and short error or truncated replies.

use std::time::Duration;

pub use domain::base::iana::exterr::ExtendedErrorCode;
use domain::{
    base::{
        Message, Name, Rtype, ToName,
        iana::{Class, Opcode, OptRcode},
        message_builder::AdditionalBuilder,
        opt::{
            Opt, OptRecord,
            exterr::ExtendedError,
            keepalive::{IdleTimeout, TcpKeepalive},
        },
        wire::Composer,
    },
    rdata::Soa,
};
use thiserror::Error;

use super::{EncodeMessageError, QueryMetadata, RECORD_FIELDS_LEN, ResponseLimit};
use crate::dns::{LibraryError, query::EDNS_UDP_PAYLOAD_SIZE, tsig::TransferSigner};

/// A UDP answer to a query without EDNS is at most 512 octets (RFC 1035,
/// Section 4.2.1).
pub const UDP_PAYLOAD_SIZE_WITHOUT_EDNS: u16 = 512;

/// The wire size of the OPT record a response carries, options aside.
pub(crate) const OPT_RECORD_LEN: usize = 1 + RECORD_FIELDS_LEN;

/// The wire size of the edns-tcp-keepalive option with its timeout.
pub(crate) const KEEPALIVE_OPTION_LEN: usize = 6;

/// Request EDNS metadata or its format error; requests with OPT receive OPT (RFC 6891).
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
    pub(crate) fn push_response_opt<Target: Composer>(
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

/// Keepalive policy: none for UDP, idle timeout for streams (RFC 7828, Section 3.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keepalive {
    None,
    IdleTimeout(Duration),
}

impl Keepalive {
    /// Advertise the TCP idle timeout (RFC 7828, Section 3.3.2); none over UDP.
    pub(crate) fn tcp_keepalive(self) -> Option<TcpKeepalive> {
        let Keepalive::IdleTimeout(idle_timeout) = self else {
            return None;
        };
        let Ok(timeout) = IdleTimeout::try_from(idle_timeout) else {
            return None;
        };

        Some(TcpKeepalive::new(Some(timeout)))
    }

    /// Use the request's transport and EDNS advertisement for every response encoder.
    pub(crate) fn response_limit(self, edns: Edns) -> ResponseLimit {
        match self {
            Keepalive::IdleTimeout(_) => ResponseLimit::STREAM,
            Keepalive::None => match edns {
                Edns::Present {
                    udp_payload_size, ..
                } => ResponseLimit::udp(udp_payload_size),
                _ => ResponseLimit::UDP,
            },
        }
    }
}

/// An inbound message the listener could not read as a query.
#[derive(Debug, Error)]
pub enum ParseQueryError {
    #[error("failed to parse DNS message: {0}")]
    Malformed(#[source] LibraryError),
    #[error("no question in DNS query")]
    NoQuestion(Box<QueryMetadata>),
    #[error("unreadable DNS message sections")]
    UnreadableSections(Box<QueryMetadata>),
    #[error("non-IN class {class} in DNS QUERY record")]
    ForeignRecordClass {
        class: Class,
        query_metadata: Box<QueryMetadata>,
    },
}

impl ParseQueryError {
    /// Preserve readable metadata so the listener can authenticate before replying.
    pub fn query_metadata(&self) -> Option<&QueryMetadata> {
        match self {
            Self::NoQuestion(query_metadata)
            | Self::UnreadableSections(query_metadata)
            | Self::ForeignRecordClass { query_metadata, .. } => Some(query_metadata),
            Self::Malformed(_) => None,
        }
    }
}

/// Require one question for supported QUERY operations; RFC 9619 rejects counts above one.
fn question_count_error(opcode: Opcode, count: u16) -> Option<OptRcode> {
    (opcode == Opcode::QUERY && count != 1).then_some(OptRcode::FORMERR)
}

/// Read an opcode without requiring any particular body layout.
pub fn extract_opcode(message: &[u8]) -> Option<Opcode> {
    Message::from_octets(message)
        .ok()
        .map(|message| message.header().opcode())
}

/// Detect QR=1 replies, which must not trigger another reply to a spoofed source.
pub fn is_response(message: &[u8]) -> bool {
    Message::from_octets(message).is_ok_and(|message| message.header().qr())
}

/// A query's question, EDNS metadata, and transfer parameters.
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
        let message = Message::from_octets(data)
            .map_err(|error| ParseQueryError::Malformed(Box::new(error)))?;

        if !super::has_readable_sections(data) {
            return Err(ParseQueryError::UnreadableSections(Box::new(
                QueryMetadata::from_message(&message, keepalive),
            )));
        }

        let query_id = message.header().id();
        let opcode = message.header().opcode();
        let rd = message.header().rd();
        let edns = Edns::from_message(&message);

        let question = message.first_question().ok_or_else(|| {
            ParseQueryError::NoQuestion(Box::new(QueryMetadata::from_message(&message, keepalive)))
        })?;

        let qname = question.qname().to_name::<Vec<u8>>();
        let qtype = question.qtype();
        let qclass = question.qclass();
        let question_count = message.header_counts().qdcount();

        // Dispatch rejects other question counts/classes with their own errors.
        if opcode == Opcode::QUERY
            && qclass == Class::IN
            && question_count == 1
            && let Some(class) = foreign_record_class(&message)
        {
            return Err(ParseQueryError::ForeignRecordClass {
                class,
                query_metadata: Box::new(QueryMetadata::from_message(&message, keepalive)),
            });
        }

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
            question_count,
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
        self.keepalive.tcp_keepalive()
    }

    /// Use the request's transport and EDNS advertisement for every response encoder.
    pub fn response_limit(&self) -> ResponseLimit {
        self.keepalive.response_limit(self.edns)
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
        QueryMetadata::from(self).build_signed_truncated_response(signer)
    }

    /// Sign an error with the accepted key (RFC 8945, Section 5.3).
    pub fn build_signed_error_response(
        &self,
        rcode: OptRcode,
        ede: Option<ExtendedErrorCode>,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        QueryMetadata::from(self).build_signed_error_response(rcode, ede, signer)
    }
}

/// General QUERY records are IN; OPT and TSIG have their own CLASS semantics.
fn foreign_record_class(message: &Message<&[u8]>) -> Option<Class> {
    for section in [message.answer(), message.authority(), message.additional()] {
        let Ok(section) = section else {
            continue;
        };

        for record in section {
            let Ok(record) = record else {
                break;
            };

            if matches!(record.rtype(), Rtype::OPT | Rtype::TSIG) {
                continue;
            }
            if record.class() != Class::IN {
                return Some(record.class());
            }
        }
    }

    None
}

/// Read the client's serial from the IXFR authority SOA.
fn extract_ixfr_serial(message: &Message<&[u8]>) -> Option<u32> {
    message
        .authority()
        .ok()?
        .limit_to::<Soa<_>>()
        .find_map(Result::ok)
        .map(|record| record.data().serial().into_int())
}
