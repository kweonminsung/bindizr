//! Asking a zone's parent whether it still delegates trust to the zone: the
//! DS RRset the zone's `parent_ns_addrs` serve for the child.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use bindizr_core::{
    config,
    dns::{
        message::{Name, Rtype},
        name::ZoneName,
        query::{DsRrset, build_edns_question, extract_ds_rrset},
    },
    model::zone::Zone,
};

/// What the parent zone's servers said about the zone's DS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentDs {
    /// The nameservers asked, as `host[:port]` entries from the zone's
    /// `parent_ns_addrs`.
    pub ns_addrs: Vec<String>,
    /// Each server's answer in `ns_addrs` order: its DS RRset, or `None` when
    /// it serves none. Kept apart because dropping trust is unsafe while any
    /// server still serves a DS, and promoting a key until every server does.
    pub answers: Vec<Option<DsRrset>>,
}

/// Ask every parent server for the zone's DS RRset. `Err` when the zone
/// names no parent or any server fails to answer: silence never reads as
/// absence.
pub async fn probe_parent_ds(zone: &Zone) -> Result<ParentDs, String> {
    let dns_config = &config::bindizr_config().dns;
    let timeout = Duration::from_secs(dns_config.notify_timeout_secs);

    let raw = zone.parent_ns_addrs.as_deref().ok_or(
        "the zone names no parent nameservers; set them with 'dnssec set --parent-ns-addrs'",
    )?;
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
) -> Result<Vec<(String, Vec<SocketAddr>)>, String> {
    let mut servers = Vec::new();
    for (entry, result) in super::resolve_address_entries(raw, timeout).await {
        match result {
            Ok(addrs) => servers.push((entry, addrs)),
            Err(e) => return Err(format!("parent server '{}' did not resolve: {}", entry, e)),
        }
    }
    if servers.is_empty() {
        return Err("the zone's parent nameserver addresses name no server".to_string());
    }
    Ok(servers)
}

/// Ask every server for the zone's DS RRset in parallel, reporting each
/// answer in `servers` order; a server none of whose addresses answers
/// fails the probe.
async fn query_ds(
    zone_name: &ZoneName,
    servers: &[(String, Vec<SocketAddr>)],
    timeout: Duration,
) -> Result<Vec<Option<DsRrset>>, String> {
    let qname = Name::<Vec<u8>>::from_str(zone_name.as_str())
        .map_err(|e| format!("invalid zone name: {}", e))?;

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
            Ok(Err(e)) => failures.push(format!("{}: {}", entry, e)),
            Err(e) => failures.push(format!("{}: probe task failed: {}", entry, e)),
        }
    }
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    Ok(answers)
}

/// Ask one server, at its addresses in order, reporting the first answer
/// (on failure, the last one tried).
async fn query_ds_at(
    qname: &Name<Vec<u8>>,
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<Option<DsRrset>, String> {
    let mut last_error = None;
    for addr in addrs {
        let (query_id, query) = build_edns_question(false, qname, Rtype::DS);
        let result = super::exchange_with_tcp_fallback(*addr, timeout, &query, "DS query")
            .await
            .and_then(|response| extract_ds_rrset(query_id, qname, &response));
        match result {
            Ok(rrset) => return Ok(rrset),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| "no address".to_string()))
}

#[cfg(test)]
pub(crate) mod tests;
