//! Unix-socket control channel between the CLI and the running daemon.

use std::io;

use tokio::net::UnixStream;

pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod types;

/// Primary path for the daemon's Unix socket.
pub(crate) const SOCKET_FILE_PATH: &str = "/run/bindizr/bindizr.sock";
/// Fallback socket path used when the primary path is unavailable.
pub(crate) const FALLBACK_SOCKET_FILE_PATH: &str = "/tmp/bindizr/bindizr.sock";

/// Whether a socket peer may drive the daemon: its own user, or root.
pub(crate) fn is_trusted_peer(peer_uid: u32, own_uid: u32) -> bool {
    peer_uid == own_uid || peer_uid == 0
}

/// The uid this process runs as, read from the kernel through a socket pair:
/// the credentials it reports for the far end are our own.
pub(crate) fn read_own_uid() -> io::Result<u32> {
    let (near, _far) = UnixStream::pair()?;
    Ok(near.peer_cred()?.uid())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    /// Verify that only the daemon's own user and root count as trusted peers.
    #[test]
    fn is_trusted_peer_admits_own_user_and_root() {
        assert!(is_trusted_peer(10001, 10001));
        assert!(is_trusted_peer(0, 10001));
        assert!(!is_trusted_peer(1000, 10001));
        // The daemon running as root admits root, and nobody else.
        assert!(is_trusted_peer(0, 0));
        assert!(!is_trusted_peer(1000, 0));
    }

    /// Verify that `read_own_uid` reports the uid that owns what this process creates.
    #[tokio::test]
    async fn read_own_uid_matches_the_owner_of_a_created_file() {
        let dir = tempfile::tempdir().unwrap();
        let owner = std::fs::metadata(dir.path()).unwrap().uid();

        assert_eq!(read_own_uid().unwrap(), owner);
    }
}
