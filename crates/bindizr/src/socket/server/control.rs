use bindizr_service::error::ServiceError;
use bindizr_service::types::MessageResponse;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};

use crate::socket::server::SocketContext;
use crate::socket::types::DaemonResponse;

/// Daemon lifecycle transitions requestable over the control socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonControl {
    Shutdown,
    Restart,
}

/// Acknowledges the one transition this daemon can take.
#[derive(Debug)]
pub(crate) struct DaemonControlSender {
    sender: Sender<DaemonControl>,
    accepted: Mutex<Option<DaemonControl>>,
}

impl DaemonControlSender {
    /// Accept the first transition and acknowledge repeats while the receiver is open.
    async fn send(&self, control: DaemonControl) -> Result<(), ServiceError> {
        let mut accepted = self.accepted.lock().await;

        if self.sender.is_closed() {
            return Err(ServiceError::internal("daemon control channel is closed"));
        }

        match *accepted {
            Some(previous) if previous == control => return Ok(()),
            Some(_) => {
                return Err(ServiceError::invalid_input(
                    "the daemon already accepted a different control transition",
                ));
            }
            None => {}
        }

        self.sender.try_send(control).map_err(|error| {
            ServiceError::internal_with_source(
                "failed to queue the daemon control transition",
                error,
            )
        })?;
        *accepted = Some(control);
        Ok(())
    }
}

/// Build the control channel: the sender lives in the socket server, the daemon's
/// lifecycle loop awaits the receiver.
pub(crate) fn channel() -> (DaemonControlSender, Receiver<DaemonControl>) {
    let (sender, receiver) = mpsc::channel(1);
    let sender = DaemonControlSender {
        sender,
        accepted: Mutex::new(None),
    };
    (sender, receiver)
}

/// Request daemon shutdown and acknowledge the control request.
pub(crate) async fn shutdown(
    socket_cx: &SocketContext,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    socket_cx.control().send(DaemonControl::Shutdown).await?;
    let message = "Bindizr is shutting down".to_string();
    Ok(MessageResponse { message }.into())
}

/// Request daemon restart and acknowledge the control request.
pub(crate) async fn restart(
    socket_cx: &SocketContext,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    socket_cx.control().send(DaemonControl::Restart).await?;
    let message = "Bindizr is restarting".to_string();
    Ok(MessageResponse { message }.into())
}

/// Reload the daemon configuration and return the result.
pub(crate) fn reload_config(
    socket_cx: &SocketContext,
) -> Result<DaemonResponse<MessageResponse>, ServiceError> {
    let changed = socket_cx.reloader().reload(socket_cx.daemon())?;

    let message = if changed.is_empty() {
        "Configuration reloaded; nothing changed".to_string()
    } else {
        format!("Configuration reloaded: {} changed", changed.join(", "))
    };

    Ok(MessageResponse { message }.into())
}

#[cfg(test)]
mod tests {
    use bindizr_service::error::ErrorCode;

    use super::*;

    /// Verify that the daemon acknowledges exactly the one transition it accepted.
    #[tokio::test]
    async fn control_channel_accepts_one_transition() {
        let (sender, mut receiver) = channel();
        sender.send(DaemonControl::Restart).await.unwrap();
        sender.send(DaemonControl::Restart).await.unwrap();
        let error = sender.send(DaemonControl::Shutdown).await.unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);

        assert_eq!(receiver.recv().await, Some(DaemonControl::Restart));
        sender.send(DaemonControl::Restart).await.unwrap();
        assert!(receiver.try_recv().is_err());
        assert!(sender.send(DaemonControl::Shutdown).await.is_err());

        drop(receiver);
        assert!(sender.send(DaemonControl::Restart).await.is_err());
    }
}
