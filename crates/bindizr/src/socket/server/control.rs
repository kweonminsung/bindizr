use std::{sync::OnceLock, time::Duration};

use bindizr_service::error::ServiceError;
use tokio::sync::mpsc;

use crate::socket::types::DaemonResponse;

/// Daemon lifecycle transitions requestable over the control socket.
pub(crate) enum DaemonControl {
    Shutdown,
    Restart,
}

static CONTROL_TX: OnceLock<mpsc::Sender<DaemonControl>> = OnceLock::new();

/// Create the control channel; the daemon main loop awaits the receiver.
pub(crate) fn init() -> mpsc::Receiver<DaemonControl> {
    let (tx, rx) = mpsc::channel(1);
    let _ = CONTROL_TX.set(tx);
    rx
}

pub(crate) fn shutdown() -> Result<DaemonResponse, ServiceError> {
    request(DaemonControl::Shutdown)?;
    Ok(DaemonResponse {
        message: "Bindizr is shutting down".to_string(),
        data: serde_json::Value::Null,
    })
}

pub(crate) fn restart() -> Result<DaemonResponse, ServiceError> {
    request(DaemonControl::Restart)?;
    Ok(DaemonResponse {
        message: "Bindizr is restarting".to_string(),
        data: serde_json::Value::Null,
    })
}

/// Deliver the transition after a short delay so the command response reaches
/// the client before the daemon tears down.
fn request(control: DaemonControl) -> Result<(), ServiceError> {
    let tx = CONTROL_TX
        .get()
        .ok_or_else(|| ServiceError::internal("Daemon control channel is not initialized"))?
        .clone();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(control).await;
    });

    Ok(())
}
