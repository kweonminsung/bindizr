use super::*;

#[tokio::test]
async fn prepare_socket_path_creates_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("run").join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();

    prepare_socket_path(socket_path).await.unwrap();

    assert!(Path::new(socket_path).parent().unwrap().exists());
}

#[tokio::test]
async fn prepare_socket_path_removes_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = match UnixListener::bind(socket_path) {
        Ok(listener) => listener,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("failed to bind test socket: {}", e),
    };
    drop(listener);

    prepare_socket_path(socket_path).await.unwrap();

    assert!(!Path::new(socket_path).exists());
}

#[tokio::test]
async fn prepare_socket_path_rejects_active_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    let listener = match UnixListener::bind(socket_path) {
        Ok(listener) => listener,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("failed to bind test socket: {}", e),
    };

    let err = prepare_socket_path(socket_path).await.unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert!(Path::new(socket_path).exists());
    drop(listener);
}

#[tokio::test]
async fn prepare_socket_path_rejects_non_socket_file() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bindizr.sock");
    let socket_path = socket_path.to_str().unwrap();
    std::fs::write(socket_path, "not a socket").unwrap();

    let err = prepare_socket_path(socket_path).await.unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert!(Path::new(socket_path).exists());
}
