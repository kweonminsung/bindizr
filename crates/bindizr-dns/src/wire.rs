//! Writing and reading the frames [`bindizr_core::dns::message`] composes:
//! the 2-byte length prefix of DNS over TCP (RFC 1035, Section 4.2.2) and the
//! size-driven flushing a zone transfer streams with.

use bindizr_core::dns::{
    DNS_TCP_MAX_SIZE,
    message::{DnsMessageBuilder, encode_tcp_message},
};

use crate::error::XfrError;

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

async fn write_frame<W>(writer: &mut W, frame: &[u8]) -> Result<(), XfrError>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    writer.write_all(frame).await.map_err(XfrError::IoError)?;
    writer.flush().await.map_err(XfrError::IoError)
}

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

    let len = u16::from_be_bytes(len_buf) as usize;

    if len > DNS_TCP_MAX_SIZE {
        return Err(XfrError::ProtocolError(format!(
            "Message too large: {} bytes",
            len
        )));
    }

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

pub(crate) async fn write_tcp_message<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), XfrError> {
    let encoded = encode_tcp_message(message)?;
    write_frame(writer, &encoded).await
}
