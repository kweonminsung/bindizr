use bindizr_core::dns::message::encode_tcp_message;

use super::*;

/// Decode a TCP DNS frame from the supplied test bytes.
async fn read(bytes: &[u8]) -> Result<Vec<u8>, XfrError> {
    read_tcp_message(&mut &bytes[..], &mut Vec::new()).await
}

/// Verify that a written message reads back whole.
#[tokio::test]
async fn a_written_message_reads_back_whole() {
    let mut framed = Vec::new();
    write_frame(&mut framed, &encode_tcp_message(b"payload").unwrap())
        .await
        .unwrap();

    assert_eq!(framed[..2], 7u16.to_be_bytes());
    assert_eq!(read(&framed).await.unwrap(), b"payload");
}

/// Verify that a frame arriving with the start of the next leaves that start
/// pending, so the next read begins where this one ended.
#[tokio::test]
async fn a_frame_arriving_with_the_next_leaves_it_pending() {
    let mut framed = encode_tcp_message(b"one").unwrap();
    framed.extend_from_slice(&encode_tcp_message(b"two").unwrap());
    let mut pending = Vec::new();
    let mut reader = &framed[..];

    assert_eq!(
        read_tcp_message(&mut reader, &mut pending).await.unwrap(),
        b"one"
    );
    assert_eq!(pending, encode_tcp_message(b"two").unwrap());
    assert_eq!(
        read_tcp_message(&mut reader, &mut pending).await.unwrap(),
        b"two"
    );
    assert!(pending.is_empty());
}

/// Verify that a connection closed between messages is not a protocol error.
#[tokio::test]
async fn a_connection_closed_between_messages_is_not_a_protocol_error() {
    // The first byte is read on its own so a secondary hanging up between
    // transfers reads as EOF rather than a malformed length prefix.
    let error = read(b"").await.unwrap_err();

    assert!(matches!(error, XfrError::Closed), "{error:?}");
}

/// An `AsyncRead` whose peer left without close_notify, as rustls
/// reports it.
struct AbruptEof;

impl AsyncRead for AbruptEof {
    /// Fail every read the way rustls does when close_notify never came.
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _task_cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::new(
            ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        )))
    }
}

/// Verify that a TLS peer leaving without close_notify between messages
/// is not a protocol error.
#[tokio::test]
async fn a_peer_leaving_without_close_notify_is_not_a_protocol_error() {
    let error = read_tcp_message(&mut AbruptEof, &mut Vec::new())
        .await
        .unwrap_err();

    assert!(matches!(error, XfrError::Closed), "{error:?}");
}

/// Verify that a truncated length prefix is a protocol error.
#[tokio::test]
async fn a_truncated_length_prefix_is_a_protocol_error() {
    let error = read(&[0x00]).await.unwrap_err();

    assert!(matches!(&error, XfrError::IncompletePrefix), "{error:?}");
}

/// Verify that a body shorter than its prefix names the length it expected.
#[tokio::test]
async fn a_body_shorter_than_its_prefix_names_the_length_it_expected() {
    let error = read(&[0x00, 0x04, b'a', b'b']).await.unwrap_err();

    assert!(
        matches!(&error, XfrError::IncompleteMessage { expected: 4 }),
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

    let error = write_frame(&mut writer, &vec![0u8; 4096])
        .await
        .expect_err("the write should have timed out");

    assert!(
        matches!(&error, XfrError::WriteTimeout { secs: 30 }),
        "{error}"
    );
}
