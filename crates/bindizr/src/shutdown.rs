//! The signal every front end stops on.

use std::future::Future;

use tokio::sync::watch;
use tokio::sync::watch::Sender;

/// A watch, not a broadcast, so a server that subscribes after the trigger
/// still sees it.
#[derive(Debug, Clone)]
pub(crate) struct Shutdown {
    stop_tx: Sender<bool>,
}

impl Default for Shutdown {
    /// Create a shutdown signal that has not been triggered.
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    /// Create a shared shutdown signal.
    pub(crate) fn new() -> Self {
        Self {
            stop_tx: watch::channel(false).0,
        }
    }

    /// Signal all listeners to begin shutdown.
    pub(crate) fn trigger(&self) {
        self.stop_tx.send_replace(true);
    }

    /// Resolve once [`Shutdown::trigger`] has been called, before or after.
    pub(crate) fn waiter(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut stop_rx = self.stop_tx.subscribe();

        async move {
            // `changed` only reports transitions, so test the current value first.
            if *stop_rx.borrow_and_update() {
                return;
            }
            let _ = stop_rx.changed().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time;

    use super::*;

    /// Verify that a trigger remains visible even when the first subscriber arrives afterward.
    #[tokio::test]
    async fn waiter_observes_triggers_before_and_after_subscription() {
        let late = Shutdown::new();
        late.trigger();

        time::timeout(Duration::from_secs(1), late.waiter())
            .await
            .unwrap();

        let early = Shutdown::new();
        let waiter = early.waiter();
        early.trigger();

        time::timeout(Duration::from_secs(1), waiter).await.unwrap();
    }
}
