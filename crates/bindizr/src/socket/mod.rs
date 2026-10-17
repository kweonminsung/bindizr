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

/// Whether the CLI may drive the daemon behind `socket_path`: a trusted peer,
/// or any daemon on the primary socket when the CLI runs as root, since only
/// root prepares `/run/bindizr` while anyone can plant a socket under `/tmp`.
pub(crate) fn is_trusted_daemon(peer_uid: u32, own_uid: u32, socket_path: &str) -> bool {
    is_trusted_peer(peer_uid, own_uid) || (own_uid == 0 && socket_path == SOCKET_FILE_PATH)
}

/// Read this process's effective UID from its own Unix socket pair.
pub(crate) fn read_own_uid() -> io::Result<u32> {
    let (near, _far) = UnixStream::pair()?;
    // Keep both ends alive while reading the credentials, including on macOS.
    Ok(near.peer_cred()?.uid())
}

#[cfg(test)]
mod tests {
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

    /// Verify that root's trust in another user's daemon stops at the primary socket.
    #[test]
    fn is_trusted_daemon_extends_root_to_the_primary_socket_only() {
        assert!(is_trusted_daemon(10001, 0, SOCKET_FILE_PATH));
        assert!(is_trusted_daemon(0, 0, FALLBACK_SOCKET_FILE_PATH));
        assert!(!is_trusted_daemon(10001, 0, FALLBACK_SOCKET_FILE_PATH));
        assert!(is_trusted_daemon(1000, 1000, FALLBACK_SOCKET_FILE_PATH));
        assert!(is_trusted_daemon(0, 1000, SOCKET_FILE_PATH));
        assert!(!is_trusted_daemon(10001, 1000, SOCKET_FILE_PATH));
        assert!(!is_trusted_daemon(10001, 1000, FALLBACK_SOCKET_FILE_PATH));
    }
}
