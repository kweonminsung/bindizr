//! DNS query parsing: the question, EDNS, keepalive and the response budget.

use std::time::Duration;

use domain::base::Message;
pub use domain::base::iana::exterr::ExtendedErrorCode;
use domain::base::iana::{Class, Opcode, OptRcode, Rtype};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::opt::exterr::ExtendedError;
use domain::base::opt::keepalive::{IdleTimeout, TcpKeepalive};
use domain::base::opt::{Opt, OptRecord};
use domain::base::wire::Composer;
use domain::rdata::Soa;
use thiserror::Error;

use crate::dns::message::{EncodeMessageError, QueryMetadata, ResponseLimit};
use crate::dns::name::WireName;
use crate::dns::tsig::TransferSigner;
use crate::dns::{LibraryError, Serial, message};

/// A UDP answer to a query without EDNS is at most 512 octets (RFC 1035,
/// Section 4.2.1).
pub const UDP_PAYLOAD_SIZE_WITHOUT_EDNS: u16 = 512;

/// The EDNS UDP payload size bindizr advertises in its queries and the
/// ceiling of a UDP response it sends (DNS Flag Day 2020).
pub const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Request EDNS metadata or its format error; requests with OPT receive OPT (RFC 6891).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edns {
    Absent,
    /// One readable OPT, its size as advertised; `ResponseLimit::udp` applies
    /// the RFC 6891, Section 6.2.3 range.
    Present {
        udp_payload_size: u16,
        version: u8,
        dnssec_ok: bool,
    },
    /// More than one OPT, or one that does not parse: FORMERR (RFC 6891, Section 6.1.1).
    Malformed,
}

impl Edns {
    /// Return whether the requester asks for DNSSEC records (RFC 3225).
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
            Some(Err(_)) => return Self::Malformed,
            Some(Ok(record)) => {
                if !record.owner().is_root() {
                    return Self::Malformed;
                }
                OptRecord::from(record)
            }
            None => return Self::Absent,
        };

        if opts.next().is_some() {
            return Self::Malformed;
        }

        Self::Present {
            udp_payload_size: first.udp_payload_size(),
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
    pub(crate) fn push_response_opt<T: Composer>(
        self,
        additional: &mut AdditionalBuilder<T>,
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
                opt.set_dnssec_ok(self.dnssec_ok());

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
    /// Return the TCP idle timeout to advertise (RFC 7828, Section 3.3.2); none over UDP.
    pub(crate) fn tcp_keepalive(self) -> Option<TcpKeepalive> {
        let Self::IdleTimeout(idle_timeout) = self else {
            return None;
        };
        let timeout = IdleTimeout::try_from(idle_timeout).ok()?;

        Some(TcpKeepalive::new(Some(timeout)))
    }

    /// Return every response encoder's budget from the request's transport and EDNS advertisement.
    pub(crate) fn response_limit(self, edns: Edns) -> ResponseLimit {
        match self {
            Self::IdleTimeout(_) => ResponseLimit::STREAM,
            Self::None => match edns {
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
    NoQuestion { query_metadata: Box<QueryMetadata> },
    #[error("unreadable DNS message sections")]
    UnreadableSections { query_metadata: Box<QueryMetadata> },
    #[error("non-IN class {class} in DNS QUERY record")]
    ForeignRecordClass {
        class: Class,
        query_metadata: Box<QueryMetadata>,
    },
}

impl ParseQueryError {
    /// Return readable metadata so the listener can authenticate before replying.
    pub fn query_metadata(&self) -> Option<&QueryMetadata> {
        match self {
            Self::NoQuestion { query_metadata }
            | Self::UnreadableSections { query_metadata }
            | Self::ForeignRecordClass { query_metadata, .. } => Some(query_metadata),
            Self::Malformed(_) => None,
        }
    }

    /// Return the response code a readable failure is answered with: the EDNS
    /// error when there is one, FORMERR otherwise; `None` when unreadable.
    pub fn format_error(&self) -> Option<OptRcode> {
        self.query_metadata()
            .map(|metadata| metadata.format_error().unwrap_or(OptRcode::FORMERR))
    }
}

/// Require one question for supported QUERY operations; RFC 9619 rejects counts above one.
fn question_count_error(opcode: Opcode, count: u16) -> Option<OptRcode> {
    (opcode == Opcode::QUERY && count != 1).then_some(OptRcode::FORMERR)
}

/// Read an opcode without requiring any particular body layout.
pub fn extract_opcode(query_data: &[u8]) -> Option<Opcode> {
    Message::from_octets(query_data)
        .ok()
        .map(|message| message.header().opcode())
}

/// Read a message's ID without requiring any particular body layout.
pub fn extract_id(message_data: &[u8]) -> Option<u16> {
    Message::from_octets(message_data)
        .ok()
        .map(|message| message.header().id())
}

/// Return whether the message is a QR=1 reply, which must not trigger another reply to a spoofed source.
pub fn is_response(query_data: &[u8]) -> bool {
    Message::from_octets(query_data).is_ok_and(|message| message.header().qr())
}

/// A query's question, EDNS metadata, and transfer parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQuery {
    pub qname: WireName,
    /// Presentation form of `qname` without the trailing dot.
    pub zone_name: String,
    pub qtype: Rtype,
    /// Echoed in every response (RFC 5936, Section 2.2.2); only IN is served.
    pub qclass: Class,
    pub question_count: u16,
    pub client_serial: Option<Serial>,
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
    pub fn parse(query_data: &[u8], keepalive: Keepalive) -> Result<Self, ParseQueryError> {
        use domain::base::ToName;

        let message = Message::from_octets(query_data)
            .map_err(|error| ParseQueryError::Malformed(Box::new(error)))?;

        if !message::has_readable_sections(query_data) {
            return Err(ParseQueryError::UnreadableSections {
                query_metadata: Box::new(QueryMetadata::from_message(&message, keepalive)),
            });
        }

        let query_id = message.header().id();
        let opcode = message.header().opcode();
        let rd = message.header().rd();
        let edns = Edns::from_message(&message);

        let question = message
            .first_question()
            .ok_or_else(|| ParseQueryError::NoQuestion {
                query_metadata: Box::new(QueryMetadata::from_message(&message, keepalive)),
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

        Ok(Self {
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

    /// Return every response encoder's budget from the request's transport and EDNS advertisement.
    pub fn response_limit(&self) -> ResponseLimit {
        self.keepalive.response_limit(self.edns)
    }

    /// Return the response code for an invalid question count or EDNS record.
    pub fn format_error(&self) -> Option<OptRcode> {
        if let Some(rcode) = question_count_error(self.opcode, self.question_count) {
            return Some(rcode);
        }
        self.edns.format_error()
    }

    /// Build the truncated answer, signed when the question was.
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

/// Return the first non-IN class of an ordinary record: general QUERY records are
/// IN; OPT and TSIG have their own CLASS semantics.
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
fn extract_ixfr_serial(message: &Message<&[u8]>) -> Option<Serial> {
    message
        .authority()
        .ok()?
        .limit_to::<Soa<_>>()
        .find_map(Result::ok)
        .map(|record| Serial::from(record.data().serial().into_int()))
}
