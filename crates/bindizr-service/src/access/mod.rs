//! The access log: every management API request and nsupdate answered, written
//! off the request path by one writer task; reads require `log:read`.

use std::net::IpAddr;
use std::sync::Arc;

use bindizr_core::config::SavedRequests;
use bindizr_core::model::access_log::{AccessLog, AccessResult, AccessSource};
use bindizr_core::model::role_grant::Action;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::authorization::Caller;
use crate::error::ServiceError;
use crate::types::{AccessLogFilter, AccessLogResponse, PaginatedResponse};
use crate::{Context, pagination};

/// How many rows wait for the writer before new ones are dropped. A request
/// never waits on its row: the SQLite writer reservation would otherwise hold
/// every answer behind a long write.
const QUEUE_CAPACITY: usize = 10_000;

/// Create the queue between the front ends and the writer; the context holds
/// the sender, and `spawn` takes the receiver.
pub fn channel() -> (Sender<AccessLog>, Receiver<AccessLog>) {
    mpsc::channel(QUEUE_CAPACITY)
}

/// The access log writer, which writes what is queued before it stops.
#[derive(Debug)]
pub struct AccessLogWorker {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl AccessLogWorker {
    /// Stop taking rows and return the task that writes the queued ones.
    pub fn stop(self) -> JoinHandle<()> {
        let _ = self.stop.send(true);
        self.task
    }
}

/// Spawn the task that writes queued access log rows one at a time.
pub fn spawn(cx: Arc<Context>, mut logs: Receiver<AccessLog>) -> AccessLogWorker {
    let (stop_tx, mut stop) = watch::channel(false);

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = stop.changed() => break,

                log = logs.recv() => match log {
                    Some(log) => write(&cx, &log).await,
                    None => return,
                },
            }
        }

        // Refuse new rows, then write the ones the answered requests left.
        logs.close();

        while let Some(log) = logs.recv().await {
            write(&cx, &log).await;
        }
    });

    AccessLogWorker {
        task,
        stop: stop_tx,
    }
}

/// Write one row; a failure is logged, since the request was answered.
async fn write(cx: &Context, log: &AccessLog) {
    if let Err(error) = bindizr_db::access_log::create(cx.db(), log).await {
        log::warn!(
            "Failed to save an access log row for {} {}: {error}",
            log.method,
            log.target
        );
    }
}

/// Queue the row of an answered request. `access_log.save = "denied"`
/// keeps denials alone and `"none"` nothing; a full or closed queue drops the
/// row and counts it.
pub fn save(cx: &Context, log: AccessLog) {
    let saved = match cx.config().access_log.save {
        SavedRequests::All => true,
        SavedRequests::Denied => log.result == AccessResult::Denied,
        SavedRequests::None => false,
    };
    if !saved {
        return;
    }

    if !cx.enqueue_access_log(log) {
        cx.metrics().track_access_log_dropped();
    }
}

/// List the access log rows `filter` selects, newest first. Count and page
/// are plain statements; drift between the two is accepted.
pub async fn list(
    cx: &Context,
    caller: &Caller,
    filter: &AccessLogFilter,
) -> Result<PaginatedResponse<AccessLogResponse>, ServiceError> {
    caller.authorize_action(Action::LogRead)?;

    let filter = normalize_filter(filter)?;

    let total = bindizr_db::access_log::count_by_filter(cx.db(), &filter).await?;
    let logs = bindizr_db::access_log::list_by_filter(cx.db(), &filter).await?;

    Ok(pagination::build_paginated_response(
        logs.iter().map(AccessLogResponse::from).collect(),
        filter.limit,
        filter.offset,
        total,
    ))
}

/// Parse the listing's source, result, address and order, fold its caller name
/// to the lowercase every token and TSIG key stores, and bound its page.
fn normalize_filter(
    filter: &AccessLogFilter,
) -> Result<bindizr_db::access_log::AccessLogFilter, ServiceError> {
    let source = filter
        .source
        .as_deref()
        .map(str::trim)
        .filter(|source| !source.is_empty())
        .map(str::parse::<AccessSource>)
        .transpose()
        .map_err(ServiceError::invalid_input)?;
    let result = filter
        .result
        .as_deref()
        .map(str::trim)
        .filter(|result| !result.is_empty())
        .map(str::parse::<AccessResult>)
        .transpose()
        .map_err(ServiceError::invalid_input)?;
    let caller_name = filter
        .caller_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase);
    let client_addr = filter
        .address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(|address| {
            // Rows store an IPv4-mapped client as IPv4, so the key does too.
            address
                .parse::<IpAddr>()
                .map(|ip| ip.to_canonical().to_string())
                .map_err(|_| {
                    ServiceError::invalid_input(format!("address '{address}' is not an IP address"))
                })
        })
        .transpose()?;

    pagination::validate_time_window(filter.since, filter.until)?;

    // Newest first is the log's natural order, whatever the field.
    let defaults = bindizr_db::access_log::AccessLogFilter::default();
    let sort = pagination::parse_setting(filter.sort.as_deref(), defaults.sort)?;
    let order = pagination::parse_setting(filter.order.as_deref(), defaults.order)?;
    pagination::validate_page_limit(filter.limit)?;

    Ok(bindizr_db::access_log::AccessLogFilter {
        source,
        result,
        caller_name,
        client_addr,
        since: filter.since,
        until: filter.until,
        sort,
        order,
        limit: filter.limit,
        offset: filter.offset,
    })
}

#[cfg(test)]
mod tests;
