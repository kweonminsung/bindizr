use super::error::XfrError;
use domain::base::{
    iana::Rtype,
    Message, Name, ToName,
};

pub const DNS_TCP_MAX_SIZE: usize = 65535;

/// Parse a DNS query message from bytes
pub fn parse_query(data: &[u8]) -> Result<(Name<Vec<u8>>, Rtype, Option<u32>, u16), XfrError> {
    let message = Message::from_octets(data)
        .map_err(|e| XfrError::ProtocolError(format!("Failed to parse DNS message: {}", e)))?;

    let query_id = message.header().id();

    // Extract the first question
    let question = message
        .first_question()
        .ok_or_else(|| XfrError::ProtocolError("No question in DNS query".to_string()))?;

    let qname = question.qname().to_name::<Vec<u8>>();
    let qtype = question.qtype();

    // For IXFR, try to extract SOA from authority section (client serial)
    let client_serial = if qtype == Rtype::IXFR {
        message
            .authority()
            .ok()
            .and_then(|mut auth| {
                auth.next().and_then(|record| {
                    record.ok().and_then(|r| {
                        if r.rtype() == Rtype::SOA {
                            // Parse SOA to get serial
                            // This is simplified; in production, properly parse SOA RDATA
                            Some(0) // Placeholder
                        } else {
                            None
                        }
                    })
                })
            })
    } else {
        None
    };

    Ok((qname, qtype, client_serial, query_id))
}

/// Encode message to TCP length-prefixed format
pub fn encode_tcp_message(message: &[u8]) -> Vec<u8> {
    let len = message.len() as u16;
    let mut result = Vec::with_capacity(2 + message.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(message);
    result
}

/// Read a length-prefixed TCP DNS message
pub async fn read_tcp_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, XfrError> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 2];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| XfrError::IoError(e))?;

    let len = u16::from_be_bytes(len_buf) as usize;

    if len > DNS_TCP_MAX_SIZE {
        return Err(XfrError::ProtocolError(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut message_buf = vec![0u8; len];
    reader
        .read_exact(&mut message_buf)
        .await
        .map_err(|e| XfrError::IoError(e))?;

    Ok(message_buf)
}

/// Write a length-prefixed TCP DNS message
pub async fn write_tcp_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), XfrError> {
    use tokio::io::AsyncWriteExt;

    let encoded = encode_tcp_message(message);
    writer
        .write_all(&encoded)
        .await
        .map_err(|e| XfrError::IoError(e))?;
    writer.flush().await.map_err(|e| XfrError::IoError(e))?;

    Ok(())
}
