//! Reading an inbound query: what the listener parses once and hands to every
//! handler, and the short replies it answers without touching the zone.

pub use domain::base::iana::exterr::ExtendedErrorCode;
use domain::{
    base::{
        Message, MessageBuilder, Name, Rtype, ToName,
        iana::{Class, Opcode, OptRcode, Rcode},
        message_builder::AdditionalBuilder,
        opt::{Opt, OptRecord, exterr::ExtendedError},
    },
    rdata::{Soa, tsig::Time48},
};
use thiserror::Error;

use super::EncodeMessageError;
use crate::dns::{LibraryError, query::EDNS_UDP_PAYLOAD_SIZE, tsig::TransferSigner};

/// A UDP answer to a query without EDNS is at most 512 octets (RFC 1035,
/// Section 4.2.1).
pub(crate) const UDP_PAYLOAD_SIZE_WITHOUT_EDNS: u16 = 512;

/// The wire size of the OPT record a response carries, options aside.
pub(crate) const OPT_RECORD_LEN: usize = 11;

/// What the query said through its OPT record (RFC 6891), or what it got
/// wrong; a query that carried one is answered with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edns {
    Absent,
    /// One version-0 OPT; sizes under 512 read as 512 (Section 6.2.3).
    Present {
        udp_payload_size: u16,
    },
    /// More than one OPT, or one that does not parse: FORMERR (Section 6.1.1).
    Malformed,
    /// A version this server does not implement: BADVERS (Section 6.1.3).
    UnsupportedVersion(u8),
}

/// Append the OPT a response owes an EDNS query (RFC 6891, Section 6.1.1),
/// with `rcode`'s extended bits and `ede` when there is one.
pub(crate) fn push_opt(
    additional: &mut AdditionalBuilder<Vec<u8>>,
    rcode: OptRcode,
    ede: Option<ExtendedErrorCode>,
) {
    additional
        .opt(|opt| {
            opt.set_udp_payload_size(EDNS_UDP_PAYLOAD_SIZE);
            opt.set_rcode(rcode);
            if let Some(code) = ede {
                opt.push(&ExtendedError::<Vec<u8>>::from(code))?;
            }
            Ok(())
        })
        .expect("one OPT record fits an unlimited message");
}

/// Read the query's OPT record, if any, as the response must echo it.
fn parse_edns(message: &Message<&[u8]>) -> Edns {
    let Ok(additional) = message.additional() else {
        return Edns::Absent;
    };
    let mut opts = additional.limit_to::<Opt<_>>();
    let first = match opts.next() {
        None => return Edns::Absent,
        Some(Err(_)) => return Edns::Malformed,
        Some(Ok(record)) => OptRecord::from(record),
    };
    if opts.next().is_some() {
        return Edns::Malformed;
    }
    if first.version() != 0 {
        return Edns::UnsupportedVersion(first.version());
    }
    Edns::Present {
        udp_payload_size: first.udp_payload_size().max(UDP_PAYLOAD_SIZE_WITHOUT_EDNS),
    }
}

/// An inbound message the listener could not read as a query.
#[derive(Debug, Error)]
pub enum ParseQueryError {
    #[error("failed to parse DNS message: {0}")]
    Malformed(#[source] LibraryError),
    #[error("no question in DNS query")]
    NoQuestion,
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
    pub client_serial: Option<u32>,
    pub query_id: u16,
    pub opcode: Opcode,
    /// Copied into every response (RFC 1035, Section 4.1.1).
    pub rd: bool,
    pub edns: Edns,
}

impl ParsedQuery {
    /// Parse a DNS question and its optional IXFR serial.
    pub fn parse(data: &[u8]) -> Result<ParsedQuery, ParseQueryError> {
        let message =
            Message::from_octets(data).map_err(|e| ParseQueryError::Malformed(Box::new(e)))?;

        let query_id = message.header().id();
        let opcode = message.header().opcode();
        let rd = message.header().rd();
        let edns = parse_edns(&message);

        let question = message
            .first_question()
            .ok_or(ParseQueryError::NoQuestion)?;

        let qname = question.qname().to_name::<Vec<u8>>();
        let qtype = question.qtype();
        let qclass = question.qclass();

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
            qclass,
            client_serial,
            query_id,
            opcode,
            rd,
            edns,
        })
    }

    /// The largest UDP answer this query may get: what it advertised, capped
    /// at what bindizr sends, or 512 octets without EDNS.
    pub fn udp_payload_limit(&self) -> usize {
        let size = match self.edns {
            Edns::Present { udp_payload_size } => udp_payload_size.min(EDNS_UDP_PAYLOAD_SIZE),
            _ => UDP_PAYLOAD_SIZE_WITHOUT_EDNS,
        };
        usize::from(size)
    }

    /// FORMERR for a malformed OPT, BADVERS for a version above 0 (RFC 6891,
    /// Sections 6.1.1 and 6.1.3); `None` when the query's EDNS is in order.
    pub fn edns_error_response(&self) -> Option<Vec<u8>> {
        let rcode = match self.edns {
            Edns::Absent | Edns::Present { .. } => return None,
            Edns::Malformed => OptRcode::FORMERR,
            Edns::UnsupportedVersion(_) => OptRcode::BADVERS,
        };
        Some(self.build_response(rcode, false, None).finish())
    }

    /// An empty authoritative answer with TC set, so a transfer client asks
    /// again over TCP (RFC 1995, Section 2; RFC 5936, Section 4.1.1).
    pub fn truncated_response(&self) -> Vec<u8> {
        self.build_response(OptRcode::NOERROR, true, None).finish()
    }

    /// A response echoing this query with only `rcode` set, and the extended
    /// error beside it when the query spoke EDNS (RFC 8914).
    pub fn error_response(&self, rcode: Rcode, ede: Option<ExtendedErrorCode>) -> Vec<u8> {
        self.build_response(OptRcode::from(rcode), false, ede)
            .finish()
    }

    /// The truncated answer, signed when the question was.
    pub fn signed_truncated_response(
        &self,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        let mut additional = self.build_response(OptRcode::NOERROR, true, None);
        if let Some(signer) = signer {
            signer
                .answer(&mut additional, Time48::now())
                .map_err(|e| EncodeMessageError::Sign(Box::new(e)))?;
        }
        Ok(additional.finish())
    }

    /// The error response, signed when a key was accepted: an accepted key
    /// answers under itself, error or not (RFC 8945, Section 5.3).
    pub fn signed_error_response(
        &self,
        rcode: Rcode,
        ede: Option<ExtendedErrorCode>,
        signer: Option<&mut TransferSigner>,
    ) -> Result<Vec<u8>, EncodeMessageError> {
        let mut additional = self.build_response(OptRcode::from(rcode), false, ede);
        if let Some(signer) = signer {
            signer
                .answer(&mut additional, Time48::now())
                .map_err(|e| EncodeMessageError::Sign(Box::new(e)))?;
        }
        Ok(additional.finish())
    }

    /// A response carrying only this query's question: the header echoed,
    /// `rcode`, AA and TC when `truncated`, and the OPT an EDNS query is
    /// owed, ahead of any TSIG the caller appends.
    fn build_response(
        &self,
        rcode: OptRcode,
        truncated: bool,
        ede: Option<ExtendedErrorCode>,
    ) -> AdditionalBuilder<Vec<u8>> {
        let mut builder = MessageBuilder::new_vec();
        let header = builder.header_mut();
        header.set_id(self.query_id);
        header.set_qr(true);
        // RFC 1035, Section 4.1.1: a response echoes the request's opcode and RD.
        header.set_opcode(self.opcode);
        header.set_rd(self.rd);
        header.set_rcode(rcode.rcode());
        header.set_aa(truncated);
        header.set_tc(truncated);

        let mut question = builder.question();
        question
            .push((&self.qname, self.qtype, self.qclass))
            .expect("one question fits an unlimited message");

        let mut additional = question.additional();
        if self.edns != Edns::Absent {
            push_opt(&mut additional, rcode, ede);
        }
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
