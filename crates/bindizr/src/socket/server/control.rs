use bindizr_service::error::ServiceError;
use bindizr_service::types::MessageResponse;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::daemon;
use crate::socket::server::SocketContext;
use crate::socket::types::DaemonResponse;

/// Daemon lifecycle transitions requestable over the control socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonControl {
    Shutdown,
    Restart,
}

/// Build the control channel: the sender lives in the socket server, the daemon's
/// lifecycle loop awaits the receiver.
pub(crate) fn channel() -> (Sender<DaemonControl>, Receiver<DaemonControl>) {
    mpsc::channel(1)
}

/// Request daemon shutdown and acknowledge the control request.
pub(crate) fn shutdown(socket_cx: &SocketContext) -> DaemonResponse<MessageResponse> {
    send_control(socket_cx, DaemonControl::Shutdown);
    let message = "Bindizr is shutting down".to_string();
    DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    }
}

/// Request daemon restart and acknowledge the control request.
pub(crate) fn restart(socket_cx: &SocketContext) -> DaemonResponse<MessageResponse> {
    send_control(socket_cx, DaemonControl::Restart);
    let message = "Bindizr is restarting".to_string();
    DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    }
}

/// Reload the daemon configuration and return the result.
pub(crate) fn reload_config(
    socket_cx: &SocketContext,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let changed = daemon::reload_config(socket_cx.daemon(), socket_cx.tls())?;

    let message = if changed.is_empty() {
        "Configuration reloaded; nothing changed".to_string()
    } else {
        format!("Configuration reloaded: {} changed", changed.join(", "))
    };

    Ok(DaemonResponse {
        message: message.clone(),
        data: MessageResponse { message },
    })
}

/// Queue the lifecycle transition; the socket server's drain lets this
/// command's reply reach the client before the daemon tears down.
fn send_control(socket_cx: &SocketContext, control: DaemonControl) {
    // A transition already queued wins; a second has nothing left to do.
    let _ = socket_cx.control().try_send(control);
}
