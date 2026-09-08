//! Asking a zone's parent whether it still delegates trust to the zone: the
//! DS RRset its nameservers serve for the child. Those are the zone's
//! `parent_ns_addrs`, or are discovered through the system resolver.

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use bindizr_core::{
    config,
    dns::{
        message::{Name, Rtype},
        name::{ZoneName, join_labels},
        query::{DsRrset, build_edns_question, extract_ds_rrset, extract_ns_names},
    },
    model::zone::Zone,
};
use tokio::net::lookup_host;

/// The system resolver bindizr discovers parents through; it has no
/// recursive resolver of its own.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// What the parent zone's servers said about the zone's DS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentDs {
    /// The nameservers asked, as `host[:port]` entries: the zone's
    /// `parent_ns_addrs`, or the discovered parent's.
    pub ns_addrs: Vec<String>,
    /// Whether `servers` came from parent discovery rather than the zone.
    pub discovered: bool,
    /// Each server's answer in `servers` order: its DS RRset, or `None` when
    /// it serves none. Kept apart because dropping trust is unsafe while any
    /// server still serves a DS, and promoting a key until every server does.
    pub answers: Vec<Option<DsRrset>>,
}

/// Ask every parent server for the zone's DS RRset. `Err` when the parent
/// is unknown or any server fails to answer: silence never reads as absence.
pub async fn probe_parent_ds(zone: &Zone) -> Result<ParentDs, String> {
    let dns_config = &config::bindizr_config().dns;
    let timeout = Duration::from_secs(dns_config.notify_timeout_secs);

    let (servers, discovered) = match zone.parent_ns_addrs.as_deref() {
        Some(raw) => (resolve_parent_ns_addrs(raw, timeout).await?, false),
        None => {
            let resolvers = load_system_resolver_addrs().await?;
            let (parent, nameservers) = discover_parent(&zone.name, &resolvers, timeout).await?;
            let servers = resolve_nameservers(&parent, &nameservers, timeout).await?;
            (servers, true)
        }
    };

    let answers = query_ds(&zone.name, &servers, timeout).await?;
    Ok(ParentDs {
        ns_addrs: servers.into_iter().map(|(entry, _)| entry).collect(),
        discovered,
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

/// The system's `nameserver` entries; without any, only a zone naming its
/// parent's nameservers itself can be checked.
async fn load_system_resolver_addrs() -> Result<Vec<SocketAddr>, String> {
    let contents = tokio::fs::read_to_string(RESOLV_CONF_PATH)
        .await
        .map_err(|e| {
            format!(
                "no resolver to discover the parent with: {} could not be read ({})",
                RESOLV_CONF_PATH, e
            )
        })?;
    let addrs = parse_resolv_conf(&contents);
    if addrs.is_empty() {
        return Err(format!(
            "no resolver to discover the parent with: {} names no nameserver",
            RESOLV_CONF_PATH
        ));
    }
    Ok(addrs)
}

/// The `nameserver` entries of a resolv.conf on port 53; a scoped IPv6
/// address (`fe80::1%en0`) has no socket address and is skipped.
fn parse_resolv_conf(contents: &str) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.split(['#', ';']).next().unwrap_or_default();
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next())
                .flatten()
                .and_then(|value| value.parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

/// The closest enclosing zone: walking up the labels, the first ancestor the
/// resolver has NS records for. Returns its name (empty for the root) and
/// its nameserver names.
async fn discover_parent(
    zone_name: &ZoneName,
    resolvers: &[SocketAddr],
    timeout: Duration,
) -> Result<(String, Vec<String>), String> {
    let labels = zone_name.labels();
    for depth in 1..=labels.len() {
        let candidate = join_labels(&labels[depth..]);
        let qname = if candidate.is_empty() {
            Name::root_vec()
        } else {
            Name::<Vec<u8>>::from_str(&candidate)
                .map_err(|e| format!("invalid parent candidate '{}': {}", candidate, e))?
        };
        let nameservers = query_ns(&qname, resolvers, timeout).await?;
        if !nameservers.is_empty() {
            return Ok((candidate, nameservers));
        }
    }
    Err(format!(
        "no parent zone found above {}: the resolver returned no NS records for any ancestor",
        zone_name.as_str()
    ))
}

/// Ask the resolvers, in order, for a name's NS records; the first that
/// answers decides.
async fn query_ns(
    qname: &Name<Vec<u8>>,
    resolvers: &[SocketAddr],
    timeout: Duration,
) -> Result<Vec<String>, String> {
    let mut last_error = None;
    for resolver in resolvers {
        let (query_id, query) = build_edns_question(true, qname, Rtype::NS);
        let result = super::exchange_with_tcp_fallback(*resolver, timeout, &query, "NS query")
            .await
            .and_then(|response| extract_ns_names(query_id, &response));
        match result {
            Ok(names) => return Ok(names),
            Err(e) => last_error = Some(format!("resolver {}: {}", resolver, e)),
        }
    }
    Err(last_error.unwrap_or_else(|| "no resolver configured".to_string()))
}

/// Addresses of the parent's nameservers on port 53; one that does not
/// resolve may be the server still serving the DS, so it fails discovery.
async fn resolve_nameservers(
    parent: &str,
    nameservers: &[String],
    timeout: Duration,
) -> Result<Vec<(String, Vec<SocketAddr>)>, String> {
    let mut servers = Vec::with_capacity(nameservers.len());
    for nameserver in nameservers {
        let addrs: Vec<SocketAddr> =
            match tokio::time::timeout(timeout, lookup_host((nameserver.as_str(), 53))).await {
                Ok(Ok(resolved)) => resolved.collect(),
                Ok(Err(e)) => {
                    return Err(format!(
                        "nameserver {} of parent zone '{}' did not resolve: {}",
                        nameserver,
                        to_display_name(parent),
                        e
                    ));
                }
                Err(_) => {
                    return Err(format!(
                        "resolving nameserver {} of parent zone '{}' timed out",
                        nameserver,
                        to_display_name(parent)
                    ));
                }
            };
        if addrs.is_empty() {
            return Err(format!(
                "nameserver {} of parent zone '{}' has no address",
                nameserver,
                to_display_name(parent)
            ));
        }
        servers.push((nameserver.clone(), addrs));
    }
    Ok(servers)
}

fn to_display_name(parent: &str) -> &str {
    if parent.is_empty() { "." } else { parent }
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
            .and_then(|response| extract_ds_rrset(query_id, &response));
        match result {
            Ok(rrset) => return Ok(rrset),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| "no address".to_string()))
}

#[cfg(test)]
mod tests;
