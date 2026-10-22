//! Writing and reading the frames [`bindizr_core::dns::message`] composes:
//! the 2-byte length prefix of DNS over TCP (RFC 1035, Section 4.2.2).

use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::timeout,
};

use crate::dns::error::DnsError;

/// Frame write deadline; prevents a stalled receiver from holding a listener slot indefinitely.
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Write a length-prefixed DNS TCP frame.
pub(crate) async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), DnsError>
where
    W: AsyncWrite + Unpin,
{
    let write = async {
        writer.write_all(frame).await?;
        writer.flush().await
    };

    match timeout(TCP_WRITE_TIMEOUT, write).await {
        Ok(result) => result.map_err(DnsError::Io),
        Err(_) => Err(DnsError::WriteTimeout {
            secs: TCP_WRITE_TIMEOUT.as_secs(),
        }),
    }
}

/// Read one DNS message from its TCP length-prefixed frame; what arrived of
/// the next stays in `pending`, which makes the read cancel-safe.
pub(crate) async fn read_tcp_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    pending: &mut Vec<u8>,
) -> Result<Vec<u8>, DnsError> {
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

        let read = reader.read(&mut chunk).await.map_err(DnsError::Io)?;

        if read == 0 {
            return Err(match expected {
                None if pending.is_empty() => DnsError::PeerClosed,
                None => DnsError::IncompletePrefix,
                Some(expected) => DnsError::IncompleteMessage { expected },
            });
        }

        pending.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(test)]
mod tests;
