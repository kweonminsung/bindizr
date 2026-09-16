//! Pulling a zone over TCP the way a secondary does, signed or not, so the
//! transfer path can be driven without BIND on the host.

use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use domain::{
    base::{Message, MessageBuilder, Rtype, iana::Rcode},
    rdata::tsig::Time48,
    tsig::ClientSequence,
};

use super::parse_name;
use crate::common::nsupdate::SigningKey;

/// What a zone transfer returned: the records it carried, or the RCODE that
/// refused it.
#[derive(Debug)]
pub(crate) enum TransferOutcome {
    Records(usize),
    Refused(Rcode),
}

impl TransferOutcome {
    /// The record count of a transfer that ran, panicking on a refusal.
    pub(crate) fn records(self) -> usize {
        match self {
            TransferOutcome::Records(count) => count,
            TransferOutcome::Refused(rcode) => panic!("transfer refused with {rcode}"),
        }
    }

    /// The RCODE of a refused transfer, panicking if it ran.
    pub(crate) fn refusal(self) -> Rcode {
        match self {
            TransferOutcome::Refused(rcode) => rcode,
            TransferOutcome::Records(count) => panic!("transfer returned {count} record(s)"),
        }
    }
}

/// Run an AXFR against `port`. With a key the request is signed and every
/// envelope's MAC is verified, so a server that answered unsigned — which
/// BIND would discard — fails here too.
pub(crate) fn axfr(
    port: u16,
    zone: &str,
    key: Option<&SigningKey>,
) -> Result<TransferOutcome, String> {
    let query_id = (std::process::id() as u16)
        .wrapping_add(port)
        .wrapping_add(7);
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

    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    stream.write_all(&framed).map_err(|e| e.to_string())?;

    // Keep reading frames until both boundary SOAs arrive; EOF alone is incomplete.
    let mut records = 0usize;
    let mut soa_seen = 0usize;
    while soa_seen < 2 {
        let Some(frame) = read_frame(&mut stream)? else {
            return Err(format!(
                "the transfer ended after {records} record(s) without its closing SOA"
            ));
        };
        let mut message = Message::from_octets(frame).map_err(|e| e.to_string())?;
        if message.header().rcode() != Rcode::NOERROR {
            return Ok(TransferOutcome::Refused(message.header().rcode()));
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
    Ok(TransferOutcome::Records(records))
}

/// Read the next length-prefixed DNS transfer frame.
fn read_frame(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut frame).map_err(|e| e.to_string())?;
    Ok(Some(frame))
}
