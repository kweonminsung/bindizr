//! Signed and unsigned zone transfers over TCP and TLS.

use std::io::{Read, Write};

use domain::{
    base::{Message, MessageBuilder, Rtype, iana::Rcode},
    rdata::tsig::Time48,
    tsig::ClientSequence,
};
use rustls::ClientConfig;

use super::{
    parse_name,
    transport::{connect_tcp, connect_tls, read_frame, write_frame},
    tsig::{SigningKey, parse_tsig_presence},
};

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
    let mut stream = connect_tcp(port)?;
    transfer(&mut stream, zone, key)
}

/// Run an AXFR over TLS using the client's configuration (RFC 9103).
pub(crate) fn xot(
    port: u16,
    zone: &str,
    key: Option<&SigningKey>,
    client: ClientConfig,
) -> Result<TransferResult, String> {
    transfer(&mut connect_tls(port, client)?, zone, key)
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
        .push((&parse_name(zone)?, Rtype::AXFR))
        .map_err(|e| e.to_string())?;
    let mut additional = question.additional();

    // A signed request seeds MAC verification across the response frames.
    let mut client = match key {
        Some(key) => Some(
            ClientSequence::request(key.to_tsig_key()?, &mut additional, Time48::now())
                .map_err(|e| e.to_string())?,
        ),
        None => None,
    };
    let query = additional.finish();

    write_frame(stream, &query)?;

    // Keep reading frames until both boundary SOAs arrive; EOF alone is incomplete.
    let mut records = 0usize;
    let mut soa_seen = 0usize;
    while soa_seen < 2 {
        let Some(frame) = read_frame(stream)? else {
            return Err(format!(
                "the transfer ended after {records} record(s) without its closing SOA"
            ));
        };
        let mut message = Message::from_octets(frame).map_err(|e| e.to_string())?;
        if message.header().rcode() != Rcode::NOERROR {
            return Ok(TransferResult::Refused {
                rcode: message.header().rcode(),
                signed: parse_tsig_presence(&message)?,
            });
        }
        if let Some(client) = client.as_mut() {
            client
                .answer(&mut message, Time48::now())
                .map_err(|e| format!("envelope did not verify: {e}"))?;
        }
        for record in message.answer().map_err(|e| e.to_string())? {
            let record = record.map_err(|e| e.to_string())?;
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
            .map_err(|e| format!("the signed transfer did not close cleanly: {e}"))?;
    }
    Ok(TransferResult::Records(records))
}
