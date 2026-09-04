pub(crate) mod config;
pub(crate) mod dnssec_policy;
pub(crate) mod doctor;
pub(crate) mod record;
pub(crate) mod restart;
pub(crate) mod status;
pub(crate) mod stop;
pub(crate) mod token;
pub(crate) mod tsig_key;
pub(crate) mod zone;

use std::time::Duration;

/// Poll `check` every 100ms until it yields a value, bounded by `deadline`.
/// Returns `None` on expiry.
pub(crate) async fn poll_with_deadline<T>(
    deadline: Duration,
    mut check: impl AsyncFnMut() -> Option<T>,
) -> Option<T> {
    let wait = async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some(value) = check().await {
                break value;
            }
        }
    };

    tokio::time::timeout(deadline, wait).await.ok()
}

/// Read command input from a file path, or from stdin when the path is `-`.
pub(crate) fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .map_err(|e| format!("Failed to read from stdin: {}", e))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read '{}': {}", path, e))
    }
}
