//! Writing and reading the frames [`bindizr_core::dns::message`] composes:
//! the 2-byte length prefix of DNS over TCP (RFC 1035, Section 4.2.2) and the
//! size-driven flushing a zone transfer streams with.

use std::{io::ErrorKind, time::Duration};

use bindizr_core::dns::message::{DnsMessageBuilder, EncodeMessageError, encode_tcp_message};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::timeout,
};

use crate::dns::error::XfrError;

/// How long one frame may take to reach the client. A receiver that stops
/// reading fills the send buffer and would otherwise hold its connection —
/// and the slot the listener counts — for as long as it likes.
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Add one answer, sending the frame that fills up first when it does.
pub(crate) async fn add_answer_and_flush_if_needed<W, F>(
    builder: &mut DnsMessageBuilder,
    writer: &mut W,
    messages_sent: &mut usize,
    add_answer: F,
) -> Result<(), XfrError>
where
    W: AsyncWrite + Unpin,
    F: FnOnce(&mut DnsMessageBuilder) -> Result<(), EncodeMessageError>,
{
    match builder.add_answer_or_overflow(add_answer) {
        Ok(Some(frame)) => {
            write_frame(writer, &frame).await?;
            *messages_sent += 1;
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(overflow) => {
            if let Some(frame) = overflow.frame {
                write_frame(writer, &frame).await?;
                *messages_sent += 1;
            }
            Err(XfrError::Protocol(overflow.source))
        }
    }
}

/// Send the buffered answers, if any; returns how many frames were written.
pub(crate) async fn flush_if_not_empty<W>(
    builder: &mut DnsMessageBuilder,
    writer: &mut W,
) -> Result<usize, XfrError>
where
    W: AsyncWrite + Unpin,
{
    match builder.take_frame()? {
        Some(frame) => {
            write_frame(writer, &frame).await?;
            Ok(1)
        }
        None => Ok(0),
    }
}

/// Write a length-prefixed DNS TCP frame.
async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), XfrError>
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

/// Read one DNS message from its TCP length-prefixed frame.
pub(crate) async fn read_tcp_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, XfrError> {
    let mut len_buf = [0u8; 2];
    // A TLS peer that hangs up without close_notify reads as UnexpectedEof
    // rather than as zero bytes; between messages both are the client leaving.
    match reader.read(&mut len_buf[..1]).await {
        Ok(0) => return Err(XfrError::Closed),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Err(XfrError::Closed),
        Err(e) => return Err(XfrError::Io(e)),
    }
    reader.read_exact(&mut len_buf[1..]).await.map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            XfrError::IncompletePrefix
        } else {
            XfrError::Io(e)
        }
    })?;

    // No size check: the two-octet prefix cannot name more than the limit
    // RFC 1035, Section 4.2.2 sets, so the allocation is bounded by the wire.
    let len = usize::from(u16::from_be_bytes(len_buf));
    let mut message_buf = vec![0u8; len];
    reader.read_exact(&mut message_buf).await.map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            XfrError::IncompleteMessage { expected: len }
        } else {
            XfrError::Io(e)
        }
    })?;

    Ok(message_buf)
}

/// Write one DNS message as a TCP length-prefixed frame.
pub(crate) async fn write_tcp_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), XfrError> {
    let encoded = encode_tcp_message(message)?;
    write_frame(writer, &encoded).await
}

#[cfg(test)]
mod tests;
