//! The stream one DNS connection arrived on, and the write half the queries
//! in flight on it share. The plain listener and the XoT listener accept
//! different types, and the handlers write to either alike.

use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use bindizr_core::{
    dns::message::{DnsMessageBuilder, EncodeMessageError, encode_tcp_message},
    model::transfer::TransferTransport,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::server::TlsStream;

use crate::dns::{error::XfrError, wire};

/// A connection as its listener accepted it: a plain TCP socket, or a TLS
/// session over one (XoT, RFC 9103).
#[derive(Debug)]
pub(crate) enum DnsStream {
    Tcp(TcpStream),
    /// Boxed: a TLS session dwarfs the socket beside it.
    Tls(Box<TlsStream<TcpStream>>),
}

impl DnsStream {
    /// The transport the connection arrived over, as the transfer log and
    /// the metrics record it.
    pub(crate) fn transport(&self) -> TransferTransport {
        match self {
            DnsStream::Tcp(_) => TransferTransport::Tcp,
            DnsStream::Tls(_) => TransferTransport::Tls,
        }
    }

    /// Split the connection into the half the listener reads queries from and
    /// the writer the queries in flight answer through.
    pub(crate) fn into_split(self) -> (ReadHalf<DnsStream>, ResponseWriter) {
        let transport = self.transport();
        let (reader, writer) = tokio::io::split(self);
        (
            reader,
            ResponseWriter {
                writer: Mutex::new(writer),
                transport,
            },
        )
    }
}

impl AsyncRead for DnsStream {
    /// Read from whichever stream the connection arrived on.
    fn poll_read(
        self: Pin<&mut Self>,
        task_cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            DnsStream::Tcp(stream) => Pin::new(stream).poll_read(task_cx, buf),
            DnsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(task_cx, buf),
        }
    }
}

impl AsyncWrite for DnsStream {
    /// Write to whichever stream the connection arrived on.
    fn poll_write(
        self: Pin<&mut Self>,
        task_cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            DnsStream::Tcp(stream) => Pin::new(stream).poll_write(task_cx, buf),
            DnsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(task_cx, buf),
        }
    }

    /// Flush whichever stream the connection arrived on.
    fn poll_flush(self: Pin<&mut Self>, task_cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            DnsStream::Tcp(stream) => Pin::new(stream).poll_flush(task_cx),
            DnsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(task_cx),
        }
    }

    /// Close the write side: a FIN, or a TLS close_notify ahead of it.
    fn poll_shutdown(
        self: Pin<&mut Self>,
        task_cx: &mut task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            DnsStream::Tcp(stream) => Pin::new(stream).poll_shutdown(task_cx),
            DnsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(task_cx),
        }
    }
}

/// Where a query's handler writes its response: the connection's write half,
/// shared by the queries in flight. A frame is written whole under the lock,
/// so concurrent responses intermingle only between messages (RFC 9103, Section 6.2).
#[derive(Debug)]
pub(crate) struct ResponseWriter {
    writer: Mutex<WriteHalf<DnsStream>>,
    transport: TransferTransport,
}

impl ResponseWriter {
    /// The transport the connection arrived over.
    pub(crate) fn transport(&self) -> TransferTransport {
        self.transport
    }

    /// Write one DNS message as a TCP frame.
    pub(crate) async fn write_message(&self, message: &[u8]) -> Result<(), XfrError> {
        let frame = encode_tcp_message(message)?;
        wire::write_frame(&mut *self.writer.lock().await, &frame).await
    }

    /// Add one answer, sending the frame that fills up first when it does.
    pub(crate) async fn add_answer_and_flush_if_needed<F>(
        &self,
        builder: &mut DnsMessageBuilder,
        messages_sent: &mut usize,
        add_answer: F,
    ) -> Result<(), XfrError>
    where
        F: FnOnce(&mut DnsMessageBuilder) -> Result<(), EncodeMessageError>,
    {
        match builder.add_answer_or_overflow(add_answer) {
            Ok(Some(frame)) => {
                wire::write_frame(&mut *self.writer.lock().await, &frame).await?;
                *messages_sent += 1;
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(overflow) => {
                if let Some(frame) = overflow.frame {
                    wire::write_frame(&mut *self.writer.lock().await, &frame).await?;
                    *messages_sent += 1;
                }
                Err(XfrError::Protocol(overflow.source))
            }
        }
    }

    /// Send the buffered answers, if any; returns how many frames were written.
    pub(crate) async fn flush_if_not_empty(
        &self,
        builder: &mut DnsMessageBuilder,
    ) -> Result<usize, XfrError> {
        match builder.take_frame()? {
            Some(frame) => {
                wire::write_frame(&mut *self.writer.lock().await, &frame).await?;
                Ok(1)
            }
            None => Ok(0),
        }
    }

    /// Close the write side: a FIN, or a TLS close_notify ahead of it.
    pub(crate) async fn shutdown(&self) -> io::Result<()> {
        self.writer.lock().await.shutdown().await
    }
}
