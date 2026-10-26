//! Plain/TLS DNS streams and the write half shared by concurrent queries.

use std::io;
use std::pin::Pin;
use std::task::{self, Poll};

use bindizr_core::dns::message;
use bindizr_core::dns::message::{DnsMessageBuilder, EncodeMessageError};
use bindizr_core::model::transfer::TransferTransport;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};
use tokio_rustls::server::TlsStream;

use crate::dns::error::DnsError;
use crate::dns::wire;

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
                failure: watch::channel(false).0,
            },
        )
    }
}

impl AsyncRead for DnsStream {
    /// Read from whichever stream the connection arrived on.
    fn poll_read(
        self: Pin<&mut Self>,
        task_cx: &mut task::Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            DnsStream::Tcp(stream) => Pin::new(stream).poll_read(task_cx, buffer),
            DnsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(task_cx, buffer),
        }
    }
}

impl AsyncWrite for DnsStream {
    /// Write to whichever stream the connection arrived on.
    fn poll_write(
        self: Pin<&mut Self>,
        task_cx: &mut task::Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            DnsStream::Tcp(stream) => Pin::new(stream).poll_write(task_cx, buffer),
            DnsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(task_cx, buffer),
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

/// Serialize complete frames on the shared write half so responses interleave
/// only between messages (RFC 9103, Section 6.2).
#[derive(Debug)]
pub(crate) struct ResponseWriter {
    writer: Mutex<WriteHalf<DnsStream>>,
    transport: TransferTransport,
    failure: watch::Sender<bool>,
}

impl ResponseWriter {
    /// The transport the connection arrived over.
    pub(crate) fn transport(&self) -> TransferTransport {
        self.transport
    }

    /// Stop subsequent response writes after a known transport failure.
    pub(crate) fn fail(&self) {
        self.failure.send_replace(true);
    }

    /// Wait until the connection cannot carry more responses.
    pub(crate) async fn failed(&self) {
        let mut failure = self.failure.subscribe();
        let _ = failure.wait_for(|failed| *failed).await;
    }

    /// Write a frame unless the connection has failed; notify waiters on errors.
    async fn write_frame(&self, frame: &[u8]) -> Result<(), DnsError> {
        let mut writer = self.writer.lock().await;

        if *self.failure.borrow() {
            return Err(DnsError::PeerClosed);
        }

        let result = tokio::select! {
            biased;
            () = self.failed() => Err(DnsError::PeerClosed),

            result = wire::write_frame(&mut *writer, frame) => result,
        };

        if result.is_err() {
            self.fail();
        }

        result
    }

    /// Write one DNS message as a TCP frame.
    pub(crate) async fn write_message(&self, message: &[u8]) -> Result<(), DnsError> {
        let frame = message::encode_tcp_message(message)?;
        self.write_frame(&frame).await
    }

    /// Add one answer, sending the frame that fills up first when it does.
    pub(crate) async fn add_answer_and_flush_if_needed<F>(
        &self,
        builder: &mut DnsMessageBuilder,
        messages_sent: &mut usize,
        add_answer: F,
    ) -> Result<(), DnsError>
    where
        F: FnOnce(&mut DnsMessageBuilder) -> Result<(), EncodeMessageError>,
    {
        if *self.failure.borrow() {
            return Err(DnsError::PeerClosed);
        }

        match builder.add_answer_or_overflow(add_answer) {
            Ok(Some(frame)) => {
                self.write_frame(&frame).await?;
                *messages_sent += 1;
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => {
                if let Some(frame) = error.frame {
                    self.write_frame(&frame).await?;
                    *messages_sent += 1;
                }
                Err(DnsError::Protocol(error.source))
            }
        }
    }

    /// Send the buffered answers, if any; returns how many frames were written.
    pub(crate) async fn flush_if_not_empty(
        &self,
        builder: &mut DnsMessageBuilder,
    ) -> Result<usize, DnsError> {
        match builder.take_frame()? {
            Some(frame) => {
                self.write_frame(&frame).await?;
                Ok(1)
            }
            None => Ok(0),
        }
    }

    /// Close healthy transports; suppress TLS close_notify after failure.
    pub(crate) async fn shutdown(&self) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        if *self.failure.borrow() {
            return Ok(());
        }
        writer.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::time;

    use super::*;

    /// A known failure suppresses queued frames and wakes connection waiters.
    #[tokio::test]
    async fn failed_connection_suppresses_queued_responses() {
        use tokio::io::AsyncReadExt as _;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let mut client = client.unwrap();
        let (_, writer) = DnsStream::Tcp(accepted.unwrap().0).into_split();
        let writer = Arc::new(writer);

        let guard = writer.writer.lock().await;
        let pending: Vec<_> = (0..3)
            .map(|_| {
                let writer = writer.clone();
                tokio::spawn(async move { writer.write_message(b"response").await })
            })
            .collect();

        writer.fail();

        time::timeout(Duration::from_secs(1), writer.failed())
            .await
            .unwrap();

        drop(guard);

        for task in pending {
            assert!(matches!(task.await.unwrap(), Err(DnsError::PeerClosed)));
        }

        writer.shutdown().await.unwrap();

        drop(writer);
        let mut received = Vec::new();

        time::timeout(Duration::from_secs(1), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();

        assert!(received.is_empty());
    }
}
