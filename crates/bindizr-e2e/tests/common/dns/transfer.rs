//! Signed and unsigned zone transfers over TCP and TLS.

use std::io::{Read, Write};
use std::process;

use domain::base::iana::{Class, Rcode, Rtype};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::{Message, MessageBuilder, Serial, Ttl};
use domain::rdata::Soa;
use domain::rdata::tsig::Time48;
use domain::tsig::ClientSequence;
use rustls::ClientConfig;

use crate::common::dns;
use crate::common::dns::tsig;
use crate::common::dns::tsig::SigningKey;

/// Build an IXFR query carrying the client's SOA serial.
pub(crate) fn build_ixfr_query(zone_name: &str, serial: u32) -> AdditionalBuilder<Vec<u8>> {
    let qname = dns::parse_name(zone_name).unwrap();
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(1995);
    let mut question = builder.question();
    question.push((&qname, Rtype::IXFR, Class::IN)).unwrap();
    let mut authority = question.authority();

    // RFC 1995, Section 3: the client's SOA belongs in the authority section.
    authority
        .push((
            &qname,
            Class::IN,
            Ttl::ZERO,
            Soa::new(
                qname.clone(),
                qname.clone(),
                Serial::from(serial),
                Ttl::ZERO,
                Ttl::ZERO,
                Ttl::ZERO,
                Ttl::ZERO,
            ),
        ))
        .unwrap();

    authority.additional()
}

/// Transferred record count or refusal details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferResult {
    Records(usize),
    Refused { rcode: Rcode, signed: bool },
}

impl TransferResult {
    /// Return the record count of a transfer that ran, panicking on a refusal.
    pub(crate) fn records(self) -> usize {
        match self {
            Self::Records(count) => count,
            Self::Refused { rcode, .. } => panic!("transfer refused with {rcode}"),
        }
    }

    /// Return the RCODE of a refused transfer, panicking if it ran.
    pub(crate) fn refusal(self) -> Rcode {
        match self {
            Self::Refused { rcode, .. } => rcode,
            Self::Records(count) => panic!("transfer returned {count} record(s)"),
        }
    }

    /// Return whether a refusal carried TSIG, panicking if the transfer ran.
    pub(crate) fn refusal_signed(self) -> bool {
        match self {
            Self::Refused { signed, .. } => signed,
            Self::Records(count) => panic!("transfer returned {count} record(s)"),
        }
    }
}

/// Run an AXFR over TCP, verifying the MAC chain when signed.
pub(crate) fn fetch_axfr_tcp(
    port: u16,
    zone_name: &str,
    key: Option<&SigningKey>,
) -> Result<TransferResult, String> {
    let mut stream = dns::connect_tcp(port)?;
    transfer(&mut stream, zone_name, key)
}

/// Run an AXFR over TLS using the client's configuration (RFC 9103).
pub(crate) fn fetch_axfr_tls(
    port: u16,
    zone_name: &str,
    key: Option<&SigningKey>,
    client: ClientConfig,
) -> Result<TransferResult, String> {
    transfer(&mut dns::connect_tls(port, client)?, zone_name, key)
}

/// Transfer a zone over an open stream, verifying the MAC chain when signed.
fn transfer<S: Read + Write>(
    stream: &mut S,
    zone_name: &str,
    key: Option<&SigningKey>,
) -> Result<TransferResult, String> {
    let query_id = (process::id() as u16).wrapping_add(7);
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);
    let mut question = builder.question();
    question
        .push((&dns::parse_name(zone_name)?, Rtype::AXFR))
        .map_err(|error| error.to_string())?;
    let mut additional = question.additional();

    // A signed request seeds MAC verification across the response frames.
    let mut client = match key {
        Some(key) => Some(
            ClientSequence::request(key.to_tsig_key()?, &mut additional, Time48::now())
                .map_err(|error| error.to_string())?,
        ),
        None => None,
    };
    let query = additional.finish();

    dns::write_frame(stream, &query)?;

    // Keep reading frames until both boundary SOAs arrive; EOF alone is incomplete.
    let mut records = 0usize;
    let mut soa_seen = 0usize;

    while soa_seen < 2 {
        let Some(response) = dns::read_frame(stream)? else {
            return Err(format!(
                "the transfer ended after {records} record(s) without its closing SOA"
            ));
        };
        let mut response = Message::from_octets(response).map_err(|error| error.to_string())?;

        if response.header().rcode() != Rcode::NOERROR {
            return Ok(TransferResult::Refused {
                rcode: response.header().rcode(),
                signed: tsig::parse_tsig_presence(&response)?,
            });
        }

        if let Some(client) = client.as_mut() {
            client
                .answer(&mut response, Time48::now())
                .map_err(|error| format!("envelope did not verify: {error}"))?;
        }

        for record in response.answer().map_err(|error| error.to_string())? {
            let record = record.map_err(|error| error.to_string())?;
            if record.rtype() == Rtype::SOA {
                soa_seen += 1;
            }
            records += 1;
        }
    }

    // The closing SOA must also leave the TSIG sequence complete.
    if let Some(client) = client {
        client
            .done()
            .map_err(|error| format!("the signed transfer did not close cleanly: {error}"))?;
    }

    Ok(TransferResult::Records(records))
}
