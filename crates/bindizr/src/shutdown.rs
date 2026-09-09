//! The signal every front end stops on.

use std::future::Future;

use tokio::sync::watch;

/// A watch, not a broadcast, so a server that subscribes after the trigger
/// still sees it.
#[derive(Clone)]
pub(crate) struct Shutdown {
    tx: watch::Sender<bool>,
}

impl Shutdown {
    pub(crate) fn new() -> Self {
        Self {
            tx: watch::channel(false).0,
        }
    }

    pub(crate) fn trigger(&self) {
        let _ = self.tx.send(true);
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
