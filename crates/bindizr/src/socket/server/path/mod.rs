//! Prepare and track the Unix socket file the daemon owns.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::sync::Arc;

use nix::libc::{ELOOP, O_DIRECTORY, O_NOFOLLOW};
use thiserror::Error;
use tokio::fs;
use tokio::net::{UnixListener, UnixStream};

use crate::socket;
use crate::socket::{FALLBACK_SOCKET_FILE_PATH, SOCKET_FILE_PATH, SocketFileId, SocketPathError};

/// Socket paths tried in order when the daemon starts.
const SOCKET_PATH_CANDIDATES: [&str; 2] = [SOCKET_FILE_PATH, FALLBACK_SOCKET_FILE_PATH];

/// Why the control socket could not be bound.
#[derive(Debug, Error)]
pub(crate) enum BindSocketError {
    /// Another daemon answers on the socket.
    #[error("Bindizr is already running")]
    InUse,
    /// Every candidate path failed, each with its reason.
    #[error("failed to bind the daemon Unix socket ({})", failures.iter().map(|(path, error)| format!("'{path}': {error}")).collect::<Vec<_>>().join("; "))]
    Unavailable {
        failures: Vec<(String, BindSocketPathError)>,
    },
}

/// Why one candidate path could not be bound.
#[derive(Debug, Error)]
pub(crate) enum BindSocketPathError {
    /// A daemon owns or is preparing the socket at this path.
    #[error("Bindizr is already running")]
    AlreadyRunning,
    /// Something other than a Unix socket sits at the path.
    #[error("socket path exists and is not a Unix socket: {path}")]
    NotASocket { path: String },
    /// The socket's directory is not a directory, or is reached through a symlink.
    #[error("socket directory is not a directory: {path}")]
    NotADirectory { path: String },
    /// Another user owns the socket's directory and could replace what the daemon binds there.
    #[error(
        "socket directory '{path}' is owned by uid {uid}, neither this user nor root; remove what \
         another user left there"
    )]
    ForeignDirectory { path: String, uid: u32 },
    /// A group member or another user could replace the socket entry.
    #[error("socket directory '{path}' is writable by its group or others (mode {mode:o})")]
    WritableDirectory { path: String, mode: u32 },
    #[error(transparent)]
    InvalidPath(#[from] SocketPathError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The path and identity of the Unix socket entry created by this daemon.
#[derive(Debug)]
pub(crate) struct SocketFile {
    path: String,
    id: SocketFileId,
    /// Keep the binding live while the daemon drains without accepting commands.
    _listener: Arc<UnixListener>,
}

impl SocketFile {
    /// Return the path at which the daemon bound its socket.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
}

/// Remove the daemon's socket once its listener and clients have drained.
pub(crate) async fn remove_socket_file(socket_file: SocketFile) {
    let socket_path = socket_file.path();
    let result = match fs::symlink_metadata(socket_path).await {
        Ok(metadata) if SocketFileId::from_metadata(&metadata) == Some(socket_file.id) => {
            fs::remove_file(socket_path).await
        }
        Ok(_) => return,
        Err(error) => Err(error),
    };

    if let Err(error) = result
        && error.kind() != io::ErrorKind::NotFound
    {
        log::warn!("Failed to remove the daemon socket {socket_path}: {error}");
    }
}

/// Bind the daemon's configured control socket. Owning it is what refuses a
/// second daemon, so the daemon binds before anything else it would share.
pub(crate) async fn bind() -> Result<(SocketFile, Arc<UnixListener>), BindSocketError> {
    let mut failures = Vec::new();

    for (index, path) in SOCKET_PATH_CANDIDATES.iter().enumerate() {
        let error = match bind_socket(path).await {
            Ok(bound) => return Ok(bound),
            // Another daemon already owns this socket. Trying the next candidate
            // would start a second daemon instead of reporting the conflict.
            Err(BindSocketPathError::AlreadyRunning) => return Err(BindSocketError::InUse),
            Err(error) => error,
        };

        if let Some(next) = SOCKET_PATH_CANDIDATES.get(index + 1) {
            log::warn!("Cannot use Unix socket path '{path}': {error}. Falling back to '{next}'.");
        }

        failures.push((path.to_string(), error));
    }

    Err(BindSocketError::Unavailable { failures })
}

/// Bind a Unix listener at the requested path.
async fn bind_socket(
    socket_path: &str,
) -> Result<(SocketFile, Arc<UnixListener>), BindSocketPathError> {
    let _directory_lock = lock_socket_directory(socket_path).await?;
    remove_stale_socket(socket_path).await?;

    // A daemon that bound this path after the check above answers EADDRINUSE
    // here: the same conflict, not a path to fall back from.
    let listener = UnixListener::bind(socket_path).map_err(|error| match error.kind() {
        io::ErrorKind::AddrInUse => BindSocketPathError::AlreadyRunning,
        _ => BindSocketPathError::Io(error),
    })?;
    let metadata = std::fs::symlink_metadata(socket_path)?;
    let id =
        SocketFileId::from_metadata(&metadata).ok_or_else(|| BindSocketPathError::NotASocket {
            path: socket_path.to_string(),
        })?;
    let listener = Arc::new(listener);
    let socket_file = SocketFile {
        path: socket_path.to_string(),
        id,
        _listener: listener.clone(),
    };

    Ok((socket_file, listener))
}

/// Open the trusted socket directory and hold its startup lock through bind.
async fn lock_socket_directory(socket_path: &str) -> Result<File, BindSocketPathError> {
    let parent = socket::socket_directory(socket_path)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .await?;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(parent)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotADirectory || error.raw_os_error() == Some(ELOOP) {
                BindSocketPathError::NotADirectory {
                    path: parent.display().to_string(),
                }
            } else {
                BindSocketPathError::Io(error)
            }
        })?;
    let metadata = directory.metadata()?;
    let own_uid = socket::read_own_uid()?;

    if !socket::is_trusted_directory_owner(&metadata, own_uid) {
        return Err(BindSocketPathError::ForeignDirectory {
            path: parent.display().to_string(),
            uid: metadata.uid(),
        });
    }
    if socket::directory_allows_other_writes(&metadata) {
        return Err(BindSocketPathError::WritableDirectory {
            path: parent.display().to_string(),
            mode: metadata.mode() & 0o777,
        });
    }

    // Lock the directory inode so all cooperating starters use one lock,
    // including after a stale pathname is unlinked.
    match directory.try_lock() {
        Ok(()) => Ok(directory),
        Err(TryLockError::WouldBlock) => Err(BindSocketPathError::AlreadyRunning),
        Err(TryLockError::Error(error)) => Err(BindSocketPathError::Io(error)),
    }
}

/// Probe and remove a stale socket while the directory's startup lock is held.
async fn remove_stale_socket(socket_path: &str) -> Result<(), BindSocketPathError> {
    match fs::symlink_metadata(socket_path).await {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(BindSocketPathError::NotASocket {
                    path: socket_path.to_string(),
                });
            }

            match UnixStream::connect(socket_path).await {
                Ok(_) => Err(BindSocketPathError::AlreadyRunning),
                // Socket file exists but no process is listening, so it is safe to remove.
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    Ok(fs::remove_file(socket_path).await?)
                }
                // Socket disappeared after metadata lookup, so there is nothing to remove.
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
