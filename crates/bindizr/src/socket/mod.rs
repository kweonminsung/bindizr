//! Unix-socket control channel between the CLI and the running daemon.

pub(crate) mod client;
pub(crate) mod server;
pub(crate) mod types;

/// Primary path for the daemon's Unix socket.
pub(crate) const SOCKET_FILE_PATH: &str = "/run/bindizr/bindizr.sock";
/// Fallback socket path used when the primary path is unavailable.
pub(crate) const FALLBACK_SOCKET_FILE_PATH: &str = "/tmp/bindizr/bindizr.sock";
