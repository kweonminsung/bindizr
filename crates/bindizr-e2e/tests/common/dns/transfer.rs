//! Signed and unsigned zone transfers over TCP and TLS.

use std::io::{Read, Write};

use domain::base::iana::Rcode;
use domain::base::{Message, MessageBuilder, Rtype};
use domain::rdata::tsig::Time48;
use domain::tsig::ClientSequence;
use rustls::ClientConfig;

use super::tsig::SigningKey;
use super::{transport, tsig};

/// Transferred record count or refusal details.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) enum TransferResult {
    Records(usize),
    Refused { rcode: Rcode, signed: bool },
}

impl TransferResult {
    /// The record count of a transfer that ran, panicking on a refusal.
    pub(crate) fn records(self) -> usize {
        match self {
            TransferResult::Records(count) => count,
            TransferResult::Refused { rcode, .. } => panic!("transfer refused with {rcode}"),
        }
    }

    /// The RCODE of a refused transfer, panicking if it ran.
    pub(crate) fn refusal(self) -> Rcode {
        match self {
            TransferResult::Refused { rcode, .. } => rcode,
            TransferResult::Records(count) => panic!("transfer returned {count} record(s)"),
        }
    }

    /// Whether a refusal carried TSIG, panicking if the transfer ran.
    pub(crate) fn refusal_signed(self) -> bool {
        match self {
            TransferResult::Refused { signed, .. } => signed,
            TransferResult::Records(count) => panic!("transfer returned {count} record(s)"),
        }
    }
}

/// Run an AXFR over TCP, verifying the MAC chain when signed.
pub(crate) fn axfr(
    port: u16,
    zone: &str,
    key: Option<&SigningKey>,
) -> Result<TransferResult, String> {
    let mut stream = transport::connect_tcp(port)?;
    transfer(&mut stream, zone, key)
}

/// Run an AXFR over TLS using the client's configuration (RFC 9103).
pub(crate) fn xot(
    port: u16,
    zone: &str,
    key: Option<&SigningKey>,
    client: ClientConfig,
) -> Result<TransferResult, String> {
    transfer(&mut transport::connect_tls(port, client)?, zone, key)
}

/// Transfer a zone over an open stream, verifying the MAC chain when signed.
fn transfer<S: Read + Write>(
    stream: &mut S,
    zone: &str,
    key: Option<&SigningKey>,
) -> Result<TransferResult, String> {
    let query_id = (std::process::id() as u16).wrapping_add(7);
    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_id(query_id);
    let mut question = builder.question();
    question
        .push((&super::parse_name(zone)?, Rtype::AXFR))
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

    transport::write_frame(stream, &query)?;

    // Keep reading frames until both boundary SOAs arrive; EOF alone is incomplete.
    let mut records = 0usize;
    let mut soa_seen = 0usize;

    while soa_seen < 2 {
        let Some(frame) = transport::read_frame(stream)? else {
            return Err(format!(
                "the transfer ended after {records} record(s) without its closing SOA"
            ));
        };
        let mut message = Message::from_octets(frame).map_err(|error| error.to_string())?;

        if message.header().rcode() != Rcode::NOERROR {
            return Ok(TransferResult::Refused {
                rcode: message.header().rcode(),
                signed: tsig::parse_tsig_presence(&message)?,
            });
        }

        if let Some(client) = client.as_mut() {
            client
                .answer(&mut message, Time48::now())
                .map_err(|error| format!("envelope did not verify: {error}"))?;
        }

        for record in message.answer().map_err(|error| error.to_string())? {
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
