//! The signal every front end stops on.

use std::future::Future;

use tokio::sync::watch;

/// A watch, not a broadcast, so a server that subscribes after the trigger
/// still sees it.
#[derive(Debug, Clone)]
pub(crate) struct Shutdown {
    tx: watch::Sender<bool>,
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
            tx: watch::channel(false).0,
        }
    }

    /// Signal all listeners to begin shutdown.
    pub(crate) fn trigger(&self) {
        self.tx.send_replace(true);
    }

    /// Resolves once [`Shutdown::trigger`] has been called, before or after.
    pub(crate) fn waiter(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut rx = self.tx.subscribe();
        async move {
            // `changed` only reports transitions, so test the current value first.
            if *rx.borrow_and_update() {
                return;
            }
            let _ = rx.changed().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A trigger remains visible even when the first subscriber arrives afterward.
    #[tokio::test]
    async fn waiter_observes_triggers_before_and_after_subscription() {
        let late = Shutdown::new();
        late.trigger();
        tokio::time::timeout(Duration::from_secs(1), late.waiter())
            .await
            .unwrap();

        let early = Shutdown::new();
        let waiter = early.waiter();
        early.trigger();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap();
    }
}
