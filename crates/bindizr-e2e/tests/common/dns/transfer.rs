//! Pulling a zone over TCP or TLS the way a secondary does, signed or not, so
//! the transfer path can be driven without BIND on the host.

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpStream},
    sync::Arc,
    time::Duration,
};

use domain::{
    base::{Message, MessageBuilder, Rtype, iana::Rcode},
    rdata::tsig::Time48,
    tsig::ClientSequence,
};
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};

use super::parse_name;
use crate::common::dns::nsupdate::SigningKey;

/// What a zone transfer returned: the records it carried, or the RCODE that
/// refused it.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
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

/// Run an AXFR against `port` over plain TCP. With a key the request is
/// signed and every envelope's MAC is verified, so a server that answered
/// unsigned — which BIND would discard — fails here too.
pub(crate) fn axfr(
    port: u16,
    zone: &str,
    key: Option<&SigningKey>,
) -> Result<TransferOutcome, String> {
    let mut stream = connect(port)?;
    transfer(&mut stream, zone, key)
}

/// Run an AXFR against `port` over TLS (XoT, RFC 9103) as `client` is
/// configured to; a handshake the server refuses is the transfer's error.
pub(crate) fn xot(
    port: u16,
    zone: &str,
    key: Option<&SigningKey>,
    client: ClientConfig,
) -> Result<TransferOutcome, String> {
    let tcp = connect(port)?;
    let server = ServerName::from(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let session = ClientConnection::new(Arc::new(client), server).map_err(|e| e.to_string())?;
    transfer(&mut StreamOwned::new(session, tcp), zone, key)
}

/// Send one message over TCP to the listener on `port` and return the first
/// response frame, for a test that builds its own question.
pub(crate) fn exchange_tcp(port: u16, message: &[u8]) -> Result<Vec<u8>, String> {
    exchange(&mut connect(port)?, message)
}

/// Send one message over TLS to the listener on `port` as `client` is
/// configured to, and return the first response frame.
pub(crate) fn exchange_xot(
    port: u16,
    message: &[u8],
    client: ClientConfig,
) -> Result<Vec<u8>, String> {
    let tcp = connect(port)?;
    let server = ServerName::from(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let session = ClientConnection::new(Arc::new(client), server).map_err(|e| e.to_string())?;
    exchange(&mut StreamOwned::new(session, tcp), message)
}

/// Write one framed message and read the first frame back.
fn exchange<S: Read + Write>(stream: &mut S, message: &[u8]) -> Result<Vec<u8>, String> {
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    stream.write_all(&framed).map_err(|e| e.to_string())?;
    read_frame(stream)?.ok_or_else(|| "the server closed without answering".to_string())
}

/// Connect to the listener on `port`, with a read timeout so a silent server
/// fails the test instead of hanging it.
fn connect(port: u16) -> Result<TcpStream, String> {
    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    Ok(stream)
}

/// Transfer `zone` over an open stream, verifying the signature when `key`
/// signed the request.
fn transfer<S: Read + Write>(
    stream: &mut S,
    zone: &str,
    key: Option<&SigningKey>,
) -> Result<TransferOutcome, String> {
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

    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    stream.write_all(&framed).map_err(|e| e.to_string())?;

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
pub(crate) fn read_frame<R: Read>(stream: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let mut frame = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut frame).map_err(|e| e.to_string())?;
    Ok(Some(frame))
}
