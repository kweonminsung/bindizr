//! DNS exchanges shared by the protocol tests.

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket},
    sync::Arc,
    time::Duration,
};

use domain::{
    base::{Message, message_builder::AdditionalBuilder},
    rdata::tsig::Time48,
    tsig::ClientTransaction,
};
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};

use super::tsig::SigningKey;

/// Return the original response after checking its ID and optional TSIG.
pub(crate) fn exchange_request(
    mut request: AdditionalBuilder<Vec<u8>>,
    key: Option<&SigningKey>,
    send: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<Message<Vec<u8>>, String> {
    let query_id = request.header().id();
    let client = key
        .map(|key| {
            ClientTransaction::request(key.to_tsig_key()?, &mut request, Time48::now())
                .map_err(|error| error.to_string())
        })
        .transpose()?;
    let response = send(&request.finish())?;
    let response = Message::from_octets(response).map_err(|error| error.to_string())?;

    if response.header().id() != query_id || !response.header().qr() {
        return Err("DNS response does not match the request".to_string());
    }

    if let Some(client) = client {
        // The verifier strips TSIG; retain it for the test's wire assertions.
        client
            .answer(&mut response.clone(), Time48::now())
            .map_err(|error| format!("DNS response signature did not verify: {error}"))?;
    }

    Ok(response)
}

/// Send one datagram and return the response bytes.
pub(crate) fn exchange_udp(port: u16, message: &[u8]) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    socket
        .send_to(message, ("127.0.0.1", port))
        .map_err(|error| error.to_string())?;
    let mut response = vec![0u8; usize::from(u16::MAX)];
    let (len, _) = socket
        .recv_from(&mut response)
        .map_err(|error| error.to_string())?;
    response.truncate(len);

    Ok(response)
}

/// Send one TCP message and return the first response frame.
pub(crate) fn exchange_tcp(port: u16, message: &[u8]) -> Result<Vec<u8>, String> {
    exchange(&mut connect_tcp(port)?, message)
}

/// Send one TLS message and return the first response frame.
pub(crate) fn exchange_xot(
    port: u16,
    message: &[u8],
    client: ClientConfig,
) -> Result<Vec<u8>, String> {
    exchange(&mut connect_tls(port, client)?, message)
}

/// Write one framed message and read the first frame back.
fn exchange<S: Read + Write>(stream: &mut S, message: &[u8]) -> Result<Vec<u8>, String> {
    write_frame(stream, message)?;
    read_frame(stream)?.ok_or_else(|| "the server closed without answering".to_string())
}

/// Connect to a TCP listener with bounded reads and writes.
pub(crate) fn connect_tcp(port: u16) -> Result<TcpStream, String> {
    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;

    Ok(stream)
}

/// Open a TLS stream using the test's certificate and protocol settings.
pub(crate) fn connect_tls(
    port: u16,
    client: ClientConfig,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let tcp = connect_tcp(port)?;
    let server = ServerName::from(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let session =
        ClientConnection::new(Arc::new(client), server).map_err(|error| error.to_string())?;
    Ok(StreamOwned::new(session, tcp))
}

/// Write a DNS message with its two-byte TCP length prefix.
pub(crate) fn write_frame<W: Write>(stream: &mut W, message: &[u8]) -> Result<(), String> {
    let length = u16::try_from(message.len()).map_err(|error| error.to_string())?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(message);
    stream.write_all(&frame).map_err(|error| error.to_string())
}

/// Read the next length-prefixed DNS frame.
pub(crate) fn read_frame<R: Read>(stream: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut len = [0u8; 2];

    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }

    let mut frame = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream
        .read_exact(&mut frame)
        .map_err(|error| error.to_string())?;

    Ok(Some(frame))
}
