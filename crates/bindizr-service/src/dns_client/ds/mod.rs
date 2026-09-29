//! Asking a zone's parent whether it still delegates trust to the zone: the
//! DS record set the zone's `parent_ns_addrs` serve for the child.

use std::{net::SocketAddr, time::Duration};

use bindizr_core::{
    dns::{
        dnssec::WireNameError,
        message::{Name, Rtype},
        name::ZoneName,
        query::{DsRecordSet, build_edns_question, extract_ds_record_set},
    },
    model::zone::Zone,
};
use thiserror::Error;

use super::{ExchangeError, ResolveAddressError};
use crate::Context;

/// Why the parent could not be asked, or what it failed to answer.
#[derive(Debug, Error)]
pub(crate) enum ProbeParentDsError {
    #[error("the zone names no parent nameservers; set them with 'dnssec set --parent-ns-addrs'")]
    NoParentNameservers,
    #[error("parent server '{entry}' did not resolve: {source}")]
    Unresolved {
        entry: String,
        #[source]
        source: ResolveAddressError,
    },
    #[error("the zone's parent nameserver addresses name no server")]
    NoServers,
    #[error("invalid zone name: {0}")]
    ZoneName(#[from] WireNameError),
    /// Every server that failed, in `parent_ns_addrs` order.
    #[error("{}", failures.iter().map(|(entry, error)| format!("{entry}: {error}")).collect::<Vec<_>>().join("; "))]
    Unanswered {
        failures: Vec<(String, QueryDsError)>,
    },
}

/// Why one parent server gave no DS answer.
#[derive(Debug, Error)]
pub(crate) enum QueryDsError {
    #[error(transparent)]
    Exchange(#[from] ExchangeError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ReadResponseError),
    #[error("no address")]
    NoAddress,
    #[error("probe task failed: {0}")]
    TaskFailed(#[source] tokio::task::JoinError),
}

/// What the parent zone's servers said about the zone's DS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParentDs {
    /// The nameservers asked, as `host[:port]` entries from the zone's
    /// `parent_ns_addrs`.
    pub(crate) ns_addrs: Vec<String>,
    /// Each server's answer in `ns_addrs` order: its DS record set, or `None` when
    /// it serves none. Kept apart because dropping trust is unsafe while any
    /// server still serves a DS, and promoting a key until every server does.
    pub(crate) answers: Vec<Option<DsRecordSet>>,
}

/// Ask every parent server for the zone's DS record set. `Err` when the zone
/// names no parent or any server fails to answer: silence never reads as
/// absence.
pub(crate) async fn probe_parent_ds(
    cx: &Context,
    zone: &Zone,
) -> Result<ParentDs, ProbeParentDsError> {
    let dns_config = &cx.config().dns;
    let timeout = dns_config.notify.timeout();
    let raw = zone
        .parent_ns_addrs
        .as_deref()
        .ok_or(ProbeParentDsError::NoParentNameservers)?;
    let servers = resolve_parent_ns_addrs(raw, timeout).await?;

    let answers = query_ds(&zone.name, &servers, timeout).await?;
    Ok(ParentDs {
        ns_addrs: servers.into_iter().map(|(entry, _)| entry).collect(),
        answers,
    })
}

/// The zone's configured parent servers with their addresses; one that
/// does not resolve cannot be asked, so it fails the probe.
async fn resolve_parent_ns_addrs(
    raw: &str,
    timeout: Duration,
) -> Result<Vec<(String, Vec<SocketAddr>)>, ProbeParentDsError> {
    let mut servers = Vec::new();
    for (entry, result) in super::resolve_address_entries(raw, timeout).await {
        match result {
            Ok(addrs) => servers.push((entry, addrs)),
            Err(source) => return Err(ProbeParentDsError::Unresolved { entry, source }),
        }
    }
    if servers.is_empty() {
        return Err(ProbeParentDsError::NoServers);
    }
    Ok(servers)
}

/// Ask every server for the zone's DS record set in parallel, reporting each
/// answer in `servers` order; a server none of whose addresses answers
/// fails the probe.
async fn query_ds(
    zone_name: &ZoneName,
    servers: &[(String, Vec<SocketAddr>)],
    timeout: Duration,
) -> Result<Vec<Option<DsRecordSet>>, ProbeParentDsError> {
    let qname = zone_name.to_wire_name()?;

    let mut tasks = Vec::with_capacity(servers.len());
    for (entry, addrs) in servers {
        let qname = qname.clone();
        let addrs = addrs.clone();
        tasks.push((
            entry.clone(),
            tokio::spawn(async move { query_ds_at(&qname, &addrs, timeout).await }),
        ));
    }

    let mut failures = Vec::new();
    let mut answers = Vec::with_capacity(tasks.len());
    for (entry, task) in tasks {
        match task.await {
            Ok(Ok(answer)) => answers.push(answer),
            Ok(Err(e)) => failures.push((entry, e)),
            Err(e) => failures.push((entry, QueryDsError::TaskFailed(e))),
        }
    }
    if !failures.is_empty() {
        return Err(ProbeParentDsError::Unanswered { failures });
    }
    Ok(answers)
}

/// Ask one server, at its addresses in order, reporting the first answer
/// (on failure, the last one tried).
async fn query_ds_at(
    qname: &Name<Vec<u8>>,
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<Option<DsRecordSet>, QueryDsError> {
    let mut last_error = None;
    for addr in addrs {
        let (query_id, query) = build_edns_question(false, qname, Rtype::DS);
        let result = match super::exchange_with_tcp_fallback(*addr, timeout, &query, "DS query")
            .await
        {
            Ok(response) => extract_ds_record_set(query_id, qname, &response).map_err(Into::into),
            Err(e) => Err(e.into()),
        };
        match result {
            Ok(record_set) => return Ok(record_set),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or(QueryDsError::NoAddress))
}

#[cfg(test)]
pub(crate) mod tests;
