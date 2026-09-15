//! Writing and reading the frames [`bindizr_core::dns::message`] composes:
//! the 2-byte length prefix of DNS over TCP (RFC 1035, Section 4.2.2) and the
//! size-driven flushing a zone transfer streams with.

use std::{io::ErrorKind, time::Duration};

use bindizr_core::dns::message::{DnsMessageBuilder, encode_tcp_message};
use tokio::time::timeout;

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
    W: tokio::io::AsyncWriteExt + Unpin,
    F: FnOnce(&mut DnsMessageBuilder) -> Result<(), String>,
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
            Err(XfrError::ProtocolError(overflow.message))
        }
    }
}

/// Send the buffered answers, if any; returns how many frames were written.
pub(crate) async fn flush_if_not_empty<W>(
    builder: &mut DnsMessageBuilder,
    writer: &mut W,
) -> Result<usize, XfrError>
where
    W: tokio::io::AsyncWriteExt + Unpin,
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
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let write = async {
        writer.write_all(frame).await?;
        writer.flush().await
    };
    match timeout(TCP_WRITE_TIMEOUT, write).await {
        Ok(result) => result.map_err(XfrError::IoError),
        Err(_) => Err(XfrError::IoError(std::io::Error::new(
            ErrorKind::TimedOut,
            format!(
                "the client read nothing for {} seconds",
                TCP_WRITE_TIMEOUT.as_secs()
            ),
        ))),
    }
}

/// Read one DNS message from its TCP length-prefixed frame.
pub(crate) async fn read_tcp_message<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, XfrError> {
    let mut len_buf = [0u8; 2];
    if reader
        .read(&mut len_buf[..1])
        .await
        .map_err(XfrError::IoError)?
        == 0
    {
        return Err(XfrError::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed",
        )));
    }
    reader.read_exact(&mut len_buf[1..]).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            XfrError::ProtocolError("Incomplete DNS TCP length prefix".to_string())
        } else {
            XfrError::IoError(e)
        }
    })?;

    // No size check: the two-octet prefix cannot name more than the limit
    // RFC 1035, Section 4.2.2 sets, so the allocation is bounded by the wire.
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut message_buf = vec![0u8; len];
    reader.read_exact(&mut message_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            XfrError::ProtocolError(format!(
                "Incomplete DNS TCP message: expected {} bytes",
                len
            ))
        } else {
            XfrError::IoError(e)
        }
    })?;

    Ok(message_buf)
}

/// Write one DNS message as a TCP length-prefixed frame.
pub(crate) async fn write_tcp_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), XfrError> {
    let encoded = encode_tcp_message(message)?;
    write_frame(writer, &encoded).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a TCP DNS frame from the supplied test bytes.
    async fn read(bytes: &[u8]) -> Result<Vec<u8>, XfrError> {
        read_tcp_message(&mut &bytes[..]).await
    }

    /// Verify that a written message reads back whole.
    #[tokio::test]
    async fn a_written_message_reads_back_whole() {
        let mut framed = Vec::new();
        write_tcp_message(&mut framed, b"payload").await.unwrap();

        assert_eq!(framed[..2], 7u16.to_be_bytes());
        assert_eq!(read(&framed).await.unwrap(), b"payload");
    }

    /// Verify that a connection closed between messages is not a protocol error.
    #[tokio::test]
    async fn a_connection_closed_between_messages_is_not_a_protocol_error() {
        // The first byte is read on its own so a secondary hanging up between
        // transfers reads as EOF rather than a malformed length prefix.
        let error = read(b"").await.unwrap_err();

        assert!(matches!(error, XfrError::IoError(_)), "{error:?}");
    }

    /// Verify that a truncated length prefix is a protocol error.
    #[tokio::test]
    async fn a_truncated_length_prefix_is_a_protocol_error() {
        let error = read(&[0x00]).await.unwrap_err();

        assert!(
            matches!(&error, XfrError::ProtocolError(m) if m.contains("length prefix")),
            "{error:?}"
        );
    }

    /// Verify that a body shorter than its prefix names the length it expected.
    #[tokio::test]
    async fn a_body_shorter_than_its_prefix_names_the_length_it_expected() {
        let error = read(&[0x00, 0x04, b'a', b'b']).await.unwrap_err();

        assert!(
            matches!(&error, XfrError::ProtocolError(m) if m.contains("expected 4 bytes")),
            "{error:?}"
        );
    }

    /// Verify that the largest prefix a frame can carry is accepted.
    #[tokio::test]
    async fn the_largest_prefix_a_frame_can_carry_is_accepted() {
        // Two octets of prefix make this the largest frame there is.
        let mut framed = u16::MAX.to_be_bytes().to_vec();
        framed.extend(std::iter::repeat_n(0u8, usize::from(u16::MAX)));

        assert_eq!(read(&framed).await.unwrap().len(), usize::from(u16::MAX));
    }

    /// Verify that a write no one reads gives up rather than holding the slot.
    #[tokio::test(start_paused = true)]
    async fn a_write_no_one_reads_gives_up_rather_than_holding_the_slot() {
        // One byte of buffer, and nothing draining the far end.
        let (mut writer, _unread) = tokio::io::duplex(1);

        let error = write_tcp_message(&mut writer, &vec![0u8; 4096])
            .await
            .expect_err("the write should have timed out");

        assert!(
            matches!(&error, XfrError::IoError(e) if e.kind() == ErrorKind::TimedOut),
            "{error}"
        );
    }
}
