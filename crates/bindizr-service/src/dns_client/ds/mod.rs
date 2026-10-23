//! Querying the supplied parent servers for a child zone's DS records.

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use bindizr_core::dns::{
    dnssec::EncodeWireNameError,
    message::{Name, Opcode, Rtype},
    name::ZoneName,
    query::{DsRecordSet, EDNS_UDP_PAYLOAD_SIZE, build_question, extract_ds_record_set},
};
use thiserror::Error;
use tokio::task::JoinSet;

use super::{ExchangeMessageError, ResolveAddressError};

/// Why the parent could not be asked, or what it failed to answer.
#[derive(Debug, Error)]
pub(crate) enum ProbeParentDsError {
    #[error("parent server '{entry}' did not resolve: {source}")]
    Unresolved {
        entry: String,
        #[source]
        source: ResolveAddressError,
    },
    #[error("the zone's parent nameserver addresses name no server")]
    NoServers,
    #[error("invalid zone name: {0}")]
    ZoneName(#[from] EncodeWireNameError),
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
    Exchange(#[from] ExchangeMessageError),
    #[error(transparent)]
    Response(#[from] bindizr_core::dns::query::ParseResponseError),
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
    /// Per-server DS sets in `ns_addrs` order; `None` means no DS.
    /// Removal needs all servers empty; promotion needs a match at each.
    pub(crate) answers: Vec<Option<DsRecordSet>>,
}

/// Query every supplied parent for DS; unanswered servers are errors, not absence.
pub(crate) async fn probe_parent_ds(
    zone_name: &ZoneName,
    parent_ns_addrs: &str,
    timeout: Duration,
) -> Result<ParentDs, ProbeParentDsError> {
    let servers = resolve_parent_ns_addrs(parent_ns_addrs, timeout).await?;

    let answers = query_ds(zone_name, &servers, timeout).await?;

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

/// Query parent DS sets in parallel, preserving server order; each server must answer.
async fn query_ds(
    zone_name: &ZoneName,
    servers: &[(String, Vec<SocketAddr>)],
    timeout: Duration,
) -> Result<Vec<Option<DsRecordSet>>, ProbeParentDsError> {
    let qname = zone_name.to_wire_name()?;

    let mut tasks = JoinSet::new();
    let mut targets = HashMap::with_capacity(servers.len());

    for (index, (entry, addrs)) in servers.iter().enumerate() {
        let qname = qname.clone();
        let addrs = addrs.clone();
        let task = tasks.spawn(async move { query_ds_at(&qname, &addrs, timeout).await });
        targets.insert(task.id(), (index, entry));
    }

    let mut results = Vec::with_capacity(servers.len());
    // Dropping the request also cancels every parent exchange it started.
    while let Some(result) = tasks.join_next_with_id().await {
        let (id, answer) = match result {
            Ok((id, answer)) => (id, answer),
            Err(error) => (error.id(), Err(QueryDsError::TaskFailed(error))),
        };
        // Every id belongs to this set and was registered before joining.
        let (index, entry) = targets[&id];
        results.push((index, entry, answer));
    }
    results.sort_unstable_by_key(|(index, _, _)| *index);

    let mut failures = Vec::new();
    let mut answers = Vec::with_capacity(servers.len());

    for (_, entry, answer) in results {
        match answer {
            Ok(answer) => answers.push(answer),
            Err(error) => failures.push((entry.clone(), error)),
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
        let (query_id, builder) = build_question(
            Opcode::QUERY,
            false,
            false,
            qname,
            Rtype::DS,
            Some(EDNS_UDP_PAYLOAD_SIZE),
        );
        let query = builder.finish();

        let result = match super::exchange_with_tcp_fallback(*addr, timeout, &query, "DS query")
            .await
        {
            Ok(response) => extract_ds_record_set(query_id, qname, &response).map_err(Into::into),
            Err(error) => Err(error.into()),
        };

        match result {
            Ok(record_set) => return Ok(record_set),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or(QueryDsError::NoAddress))
}

#[cfg(test)]
pub(crate) mod tests;
