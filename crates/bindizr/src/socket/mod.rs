//! Unix-socket control channel between the CLI and the running daemon.

pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod types;

use std::fs::Metadata;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::{fmt, io};

use thiserror::Error;
use tokio::net::UnixStream;

/// Primary path for the daemon's Unix socket.
pub(crate) const SOCKET_FILE_PATH: &str = "/run/bindizr/bindizr.sock";
/// Fallback socket path used when the primary path is unavailable.
pub(crate) const FALLBACK_SOCKET_FILE_PATH: &str = "/tmp/bindizr/bindizr.sock";

/// A malformed socket payload whose parser may quote a credential value.
#[derive(Error)]
#[error(
    "{:?} at line {}, column {}",
    .0.classify(),
    .0.line(),
    .0.column()
)]
struct SocketDecodeError(#[source] serde_json::Error);

impl fmt::Debug for SocketDecodeError {
    /// Show the error classification and position without the parser's payload.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// The configured socket path has no parent directory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("socket path '{path}' has no parent")]
pub(crate) struct SocketPathError {
    path: String,
}

/// Find the parent directory of a configured socket path.
fn socket_directory(socket_path: &str) -> Result<&Path, SocketPathError> {
    Path::new(socket_path)
        .parent()
        .ok_or_else(|| SocketPathError {
            path: socket_path.to_string(),
        })
}

/// Return whether someone beyond the directory owner can replace a socket entry.
fn directory_allows_other_writes(metadata: &Metadata) -> bool {
    metadata.mode() & 0o022 != 0
}

/// Return whether the directory belongs to its daemon or root.
fn is_trusted_directory_owner(metadata: &Metadata, daemon_uid: u32) -> bool {
    metadata.uid() == daemon_uid || metadata.uid() == 0
}

/// A pathname's socket identity across daemon cleanup and client polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketFileId {
    device: u64,
    inode: u64,
}

impl SocketFileId {
    /// Read a socket's identity from its metadata.
    fn from_metadata(metadata: &Metadata) -> Option<Self> {
        metadata.file_type().is_socket().then(|| Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// Return whether a socket peer may drive the daemon: its own user, or root.
pub(crate) fn is_trusted_peer(peer_uid: u32, own_uid: u32) -> bool {
    peer_uid == own_uid || peer_uid == 0
}

/// Return whether the CLI may trust its daemon peer after verifying the
/// socket directory. Root can drive another user's daemon at the primary path.
/// The `/tmp` fallback always requires trusted peer credentials.
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
