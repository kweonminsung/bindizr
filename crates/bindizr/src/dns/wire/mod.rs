//! Writing and reading the frames [`bindizr_core::dns::message`] composes:
//! the 2-byte length prefix of DNS over TCP (RFC 1035, Section 4.2.2).

use std::{io::ErrorKind, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::timeout,
};

use crate::dns::error::XfrError;

/// How long one frame may take to reach the client. A receiver that stops
/// reading fills the send buffer and would otherwise hold its connection —
/// and the slot the listener counts — for as long as it likes.
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Write a length-prefixed DNS TCP frame.
pub(crate) async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), XfrError>
where
    W: AsyncWrite + Unpin,
{
    let write = async {
        writer.write_all(frame).await?;
        writer.flush().await
    };
    match timeout(TCP_WRITE_TIMEOUT, write).await {
        Ok(result) => result.map_err(XfrError::Io),
        Err(_) => Err(XfrError::WriteTimeout {
            secs: TCP_WRITE_TIMEOUT.as_secs(),
        }),
    }
}

/// Read one DNS message from its TCP length-prefixed frame; what arrived of
/// the next stays in `pending`, which makes the read cancel-safe.
pub(crate) async fn read_tcp_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    pending: &mut Vec<u8>,
) -> Result<Vec<u8>, XfrError> {
    let mut chunk = [0u8; 4096];
    loop {
        // The two-octet prefix cannot name more than the limit RFC 1035,
        // Section 4.2.2 sets, so the allocation is bounded by the wire.
        let expected = pending
            .get(..2)
            .map(|prefix| usize::from(u16::from_be_bytes([prefix[0], prefix[1]])));
        if let Some(len) = expected
            && pending.len() >= 2 + len
        {
            let message = pending[2..2 + len].to_vec();
            pending.drain(..2 + len);
            return Ok(message);
        }

        // A TLS peer that hangs up without close_notify reads as UnexpectedEof
        // rather than as zero bytes; between messages both are the client leaving.
        let read = match reader.read(&mut chunk).await {
            Ok(read) => read,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(XfrError::Io(e)),
        };
        if read == 0 {
            return Err(match expected {
                None if pending.is_empty() => XfrError::Closed,
                None => XfrError::IncompletePrefix,
                Some(expected) => XfrError::IncompleteMessage { expected },
            });
        }
        pending.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(test)]
mod tests;
