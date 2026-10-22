//! Outbound NOTIFY transport and acknowledgement errors.
mod client;
use std::sync::Arc;

pub(crate) use client::NotifyClient;
use thiserror::Error;

use super::ExchangeMessageError;

/// Why one NOTIFY to one address was not acknowledged.
#[derive(Debug, Error)]
pub enum SendNotifyError {
    /// A socket failure shared by its pending requests.
    #[error("{0}")]
    Io(#[source] Arc<std::io::Error>),
    #[error(transparent)]
    Sign(#[from] bindizr_core::dns::tsig::SignRequestError),
    #[error(transparent)]
    Exchange(#[from] ExchangeMessageError),
    #[error(transparent)]
    Verify(#[from] bindizr_core::dns::tsig::VerifyResponseError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ParseResponseError),
    #[error("NOTIFY socket worker stopped")]
    WorkerStopped,
}

#[cfg(test)]
mod tests;
