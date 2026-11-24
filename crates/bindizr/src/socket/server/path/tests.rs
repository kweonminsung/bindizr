use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;

/// Verify that the socket directory is created owner-only.
#[tokio::test]
async fn lock_socket_directory_creates_owner_only_directory() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("run").join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    let _directory_lock = lock_socket_directory(socket_path).await.unwrap();

    let parent = fs::metadata(Path::new(socket_path).parent().unwrap()).unwrap();

    assert!(parent.is_dir());
    assert_eq!(parent.mode() & 0o777, 0o700);
}

/// Verify that startup refuses a socket directory reached through a symlink.
#[tokio::test]
async fn lock_socket_directory_rejects_symlinked_directory() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("real")).unwrap();
    std::os::unix::fs::symlink(directory.path().join("real"), directory.path().join("link"))
        .unwrap();
    let socket_path = directory.path().join("link").join("bindizr.sock");

    let error = lock_socket_directory(socket_path.to_str().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(error, BindSocketPathError::NotADirectory { .. }),
        "{error}"
    );
}

/// Verify that the socket's owner and the UID both ends read for peer authorization agree.
#[tokio::test]
async fn accepted_connection_returns_peer_uid() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    let (_, listener) = bind_socket(socket_path).await.unwrap();

    let metadata = fs::metadata(socket_path).unwrap();
    let own_uid = socket::read_own_uid().unwrap();

    assert_eq!(own_uid, metadata.uid());

    let (client, accepted) = tokio::join!(UnixStream::connect(socket_path), listener.accept());

    // macOS reports no credentials once the peer has hung up, so the client
    // stays open while the daemon side asks.
    let client = client.unwrap();
    let (stream, _) = accepted.unwrap();

    assert_eq!(stream.peer_cred().unwrap().uid(), own_uid);
    assert_eq!(client.peer_cred().unwrap().uid(), own_uid);
}

/// Verify that a stale socket is replaced only by the startup holding the directory lock.
#[tokio::test]
async fn bind_socket_serializes_stale_socket_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = UnixListener::bind(socket_path).unwrap();
    drop(listener);
    let stale_socket = SocketFileId::from_metadata(&fs::symlink_metadata(socket_path).unwrap());
    let directory_lock = lock_socket_directory(socket_path).await.unwrap();

    let error = bind_socket(socket_path).await.unwrap_err();
    assert!(matches!(error, BindSocketPathError::AlreadyRunning));
    assert_eq!(
        SocketFileId::from_metadata(&fs::symlink_metadata(socket_path).unwrap()),
        stale_socket
    );

    drop(directory_lock);
    let (socket_file, listener) = bind_socket(socket_path).await.unwrap();
    let (connection, accepted) = tokio::join!(UnixStream::connect(socket_path), listener.accept());
    assert!(connection.is_ok());
    assert!(accepted.is_ok());
    remove_socket_file(socket_file).await;
}

/// Verify that startup rejects an active socket.
#[tokio::test]
async fn bind_socket_rejects_active_socket() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = UnixListener::bind(socket_path).unwrap();

    let error = bind_socket(socket_path).await.unwrap_err();

    assert!(matches!(error, BindSocketPathError::AlreadyRunning));
    assert!(Path::new(socket_path).exists());
    drop(listener);
}

/// Verify that startup leaves a non-socket file in place.
#[tokio::test]
async fn bind_socket_rejects_non_socket_file() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    fs::write(socket_path, "not a socket").unwrap();

    let error = bind_socket(socket_path).await.unwrap_err();

    assert!(matches!(error, BindSocketPathError::NotASocket { .. }));
    assert!(Path::new(socket_path).exists());
}

/// Verify that startup leaves entries in a writable socket directory alone.
#[tokio::test]
async fn bind_socket_rejects_directories_writable_by_others() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    drop(UnixListener::bind(socket_path).unwrap());

    for mode in [0o770, 0o707] {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode)).unwrap();
        let error = bind_socket(socket_path).await.unwrap_err();

        assert!(matches!(
            error,
            BindSocketPathError::WritableDirectory { .. }
        ));
        assert!(Path::new(socket_path).exists());
    }
}

/// Verify that cleanup removes the bound socket and preserves a replacement.
#[tokio::test]
async fn remove_socket_file_keeps_a_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("bindizr.sock");
    let displaced_path = directory.path().join("bindizr-old.sock");
    let (socket_file, listener) = bind_socket(socket_path.to_str().unwrap()).await.unwrap();
    drop(listener);
    assert!(matches!(
        bind_socket(socket_file.path()).await,
        Err(BindSocketPathError::AlreadyRunning)
    ));

    fs::rename(&socket_path, &displaced_path).unwrap();
    let (replacement_file, listener) = bind_socket(socket_path.to_str().unwrap()).await.unwrap();
    drop(listener);

    remove_socket_file(socket_file).await;
    assert!(socket_path.exists());
    assert!(displaced_path.exists());

    remove_socket_file(replacement_file).await;
    assert!(!socket_path.exists());
}
