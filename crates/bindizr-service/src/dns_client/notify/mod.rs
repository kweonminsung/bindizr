//! Outbound NOTIFY transport and acknowledgement errors.

mod client;

use std::io;
use std::sync::Arc;

use bindizr_core::dns::query::ParseResponseError;
use bindizr_core::dns::tsig::{SignRequestError, VerifyResponseError};
pub(crate) use client::NotifyClient;
use thiserror::Error;

use super::ExchangeMessageError;

/// Why one NOTIFY to one address was not acknowledged.
#[derive(Debug, Error)]
pub enum SendNotifyError {
    /// A socket failure shared by its pending requests.
    #[error("{0}")]
    Io(#[source] Arc<io::Error>),
    #[error(transparent)]
    Sign(#[from] SignRequestError),
    #[error(transparent)]
    Exchange(#[from] ExchangeMessageError),
    #[error(transparent)]
    Verify(#[from] VerifyResponseError),
    #[error(transparent)]
    Response(#[from] ParseResponseError),
    #[error("NOTIFY socket worker stopped")]
    WorkerStopped,
}

#[cfg(test)]
mod tests;
