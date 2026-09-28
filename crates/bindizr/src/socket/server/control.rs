use std::time::Duration;

use bindizr_service::{error::ServiceError, types::MessageResponse};
use tokio::sync::mpsc;

use crate::socket::{
    server::{SocketContext, to_response_data},
    types::DaemonResponse,
};

/// Daemon lifecycle transitions requestable over the control socket.
pub(crate) enum DaemonControl {
    Shutdown,
    Restart,
}

/// The control channel: the sender lives in the socket server, the daemon's
/// lifecycle loop awaits the receiver.
pub(crate) fn channel() -> (mpsc::Sender<DaemonControl>, mpsc::Receiver<DaemonControl>) {
    mpsc::channel(1)
}

/// Request daemon shutdown and acknowledge the control request.
pub(crate) fn shutdown(socket_cx: &SocketContext) -> Result<DaemonResponse, ServiceError> {
    send_control(socket_cx, DaemonControl::Shutdown);
    let message = "Bindizr is shutting down".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Request daemon restart and acknowledge the control request.
pub(crate) fn restart(socket_cx: &SocketContext) -> Result<DaemonResponse, ServiceError> {
    send_control(socket_cx, DaemonControl::Restart);
    let message = "Bindizr is restarting".to_string();
    Ok(DaemonResponse {
        message: message.clone(),
        data: to_response_data(MessageResponse { message })?,
    })
}

/// Deliver the transition after a short delay so the command response reaches
/// the client before the daemon tears down.
fn send_control(socket_cx: &SocketContext, control: DaemonControl) {
    let tx = socket_cx.control().clone();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(control).await;
    });
}
