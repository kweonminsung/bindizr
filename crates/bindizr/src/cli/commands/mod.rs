pub(crate) mod completion;
pub(crate) mod config;
pub(crate) mod dnssec;
pub(crate) mod dnssec_policy;
pub(crate) mod doctor;
pub(crate) mod record;
pub(crate) mod restart;
pub(crate) mod secondary;
pub(crate) mod status;
pub(crate) mod stop;
pub(crate) mod token;
pub(crate) mod tsig_key;
pub(crate) mod zone;

use std::time::Duration;

use thiserror::Error;

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
pub(crate) fn read_input(path: &str) -> Result<String, ReadInputError> {
    if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .map_err(ReadInputError::Stdin)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|source| ReadInputError::File {
            path: path.to_string(),
            source,
        })
    }
}

/// Why command input could not be read.
#[derive(Debug, Error)]
pub(crate) enum ReadInputError {
    #[error("Failed to read from stdin: {0}")]
    Stdin(#[source] std::io::Error),
    #[error("Failed to read '{path}': {source}")]
    File {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
