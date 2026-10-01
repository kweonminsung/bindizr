//! Parsing of `host[:port]` address targets into socket addresses or deferred
//! host/port pairs.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use super::name::{LabelCharset, MAX_DOMAIN_LEN, classify_domain_label};

/// The port a `host` without one is taken to serve DNS on.
pub const DEFAULT_DNS_PORT: u16 = 53;

/// An address target: a socket address, or a host and port to resolve later.
/// Canonical by construction: the port is spelled out and a hostname is
/// lowercase, so one server has one spelling, which rows compare as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressTarget {
    Socket(SocketAddr),
    HostPort(String),
}

impl AddressTarget {
    /// Parse an address target and supply the default port when needed.
    pub fn parse(value: &str, default_port: u16) -> Self {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return AddressTarget::Socket(addr);
        }

        if let Ok(ip) = value.parse::<IpAddr>() {
            return AddressTarget::Socket(SocketAddr::new(ip, default_port));
        }

        if let Some(bracketed) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']'))
            && let Ok(ip) = bracketed.parse::<IpAddr>()
        {
            return AddressTarget::Socket(SocketAddr::new(ip, default_port));
        }

        let host_port = if has_explicit_port(value) || value.contains(':') {
            value.to_string()
        } else {
            format!("{}:{}", value, default_port)
        };
        // A trailing root dot names the same host, so one server has one spelling.
        let host_port = match host_port.rsplit_once(':') {
            Some((host, port)) => format!("{}:{}", host.strip_suffix('.').unwrap_or(host), port),
            None => host_port,
        };

        AddressTarget::HostPort(host_port.to_ascii_lowercase())
    }
}

/// The stored and presentation form: `ip:port`, `[ipv6]:port`, or `host:port`.
impl fmt::Display for AddressTarget {
    /// Write the address target in its canonical form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressTarget::Socket(addr) => fmt::Display::fmt(addr, f),
            AddressTarget::HostPort(host_port) => f.pad(host_port),
        }
    }
}

/// Binding renders the canonical form, so a query never compares a spelling
/// the parser did not produce.
impl<DB: sqlx::Database> sqlx::Type<DB> for AddressTarget
where
    String: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    /// Check whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for AddressTarget
where
    String: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.to_string().encode_by_ref(buf)
    }
}

/// The read half: the column holds the row form, so decoding never fails.
impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for AddressTarget
where
    &'r str: sqlx::Decode<'r, DB>,
{
    /// Read the row form.
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(Self::parse(
            <&str as sqlx::Decode<'r, DB>>::decode(value)?,
            DEFAULT_DNS_PORT,
        ))
    }
}

/// A wildcard listen address is not connectable; probe it via loopback.
pub fn loopback_if_unspecified(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(a) if a.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(a) if a.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        addr => addr,
    }
}

/// `host[:port]`, `ip[:port]`, or `[ipv6][:port]`: LDH labels (`_` allowed)
/// and a numeric, non-zero port, as the resolver takes them.
pub fn is_address_target(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return addr.port() != 0;
    }
    if let Some((ip, rest)) = value.strip_prefix('[').and_then(|v| v.split_once(']')) {
        return ip.parse::<IpAddr>().is_ok() && (rest.is_empty() || has_explicit_port(value));
    }
    match value.rsplit_once(':') {
        Some((host, _)) => has_explicit_port(value) && is_hostname(host),
        None => is_hostname(value),
    }
}

/// Check whether a hostname uses valid domain labels. A resolver target is an
/// LDH name with no escapes, so the dot is always a label boundary here.
fn is_hostname(value: &str) -> bool {
    let name = value.strip_suffix('.').unwrap_or(value);
    !name.is_empty()
        && name.len() <= MAX_DOMAIN_LEN
        && name
            .split('.')
            .all(|label| classify_domain_label(label, LabelCharset::LdhUnderscore).is_ok())
}

/// Check whether an address target includes a valid explicit port.
fn has_explicit_port(value: &str) -> bool {
    if let Some((_, rest)) = value.strip_prefix('[').and_then(|v| v.split_once(']')) {
        return rest.strip_prefix(':').is_some_and(is_valid_port);
    }

    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => is_valid_port(port),
        _ => false,
    }
}

/// Check whether text represents a nonzero 16-bit port.
fn is_valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests;
