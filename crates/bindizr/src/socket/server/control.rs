use std::{sync::OnceLock, time::Duration};

use bindizr_service::{error::ServiceError, types::MessageResponse};
use tokio::sync::mpsc;

use crate::socket::{server::to_response_data, types::DaemonResponse};

/// Daemon lifecycle transitions requestable over the control socket.
pub(crate) enum DaemonControl {
    Shutdown,
    Restart,
}

static CONTROL_TX: OnceLock<mpsc::Sender<DaemonControl>> = OnceLock::new();

/// Create the control channel; the daemon main loop awaits the receiver.
pub(crate) fn initialize() -> mpsc::Receiver<DaemonControl> {
    let (tx, rx) = mpsc::channel(1);
    let _ = CONTROL_TX.set(tx);
    rx
}

/// Request daemon shutdown and acknowledge the control request.
pub(crate) fn shutdown() -> Result<DaemonResponse, ServiceError> {
    send_control(DaemonControl::Shutdown)?;
    let message = "Bindizr is shutting down".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Request daemon restart and acknowledge the control request.
pub(crate) fn restart() -> Result<DaemonResponse, ServiceError> {
    send_control(DaemonControl::Restart)?;
    let message = "Bindizr is restarting".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Deliver the transition after a short delay so the command response reaches
/// the client before the daemon tears down.
fn send_control(control: DaemonControl) -> Result<(), ServiceError> {
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
