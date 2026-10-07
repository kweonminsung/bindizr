//! The stream one DNS connection arrived on. The plain listener and the XoT
//! listener accept different types, and the handlers write to either alike.

use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;

/// A connection as its listener accepted it: a plain TCP socket, or a TLS
/// session over one (XoT, RFC 9103).
#[derive(Debug)]
pub(crate) enum DnsStream {
    Tcp(TcpStream),
    /// Boxed: a TLS session dwarfs the socket beside it.
    Tls(Box<TlsStream<TcpStream>>),
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
