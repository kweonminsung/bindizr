//! Parsing of `host[:port]` address targets into socket addresses or deferred
//! host/port pairs.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;

use crate::dns::name::{MAX_DNS_LABEL_LEN, MAX_DOMAIN_LEN};

/// The port a `host` without one is taken to serve DNS on.
pub const DEFAULT_DNS_PORT: u16 = 53;

/// A socket address or hostname to resolve, with an explicit port.
/// Hostnames are lowercase so rows compare one canonical spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressTarget {
    Socket(SocketAddr),
    HostPort(String),
}

impl AddressTarget {
    /// Parse an address target and supply the default port when needed.
    pub fn parse(value: &str, default_port: u16) -> Self {
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Self::Socket(addr);
        }

        if let Ok(ip) = value.parse::<IpAddr>() {
            return Self::Socket(SocketAddr::new(ip, default_port));
        }

        if let Some(bracketed) = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            && let Ok(ip) = bracketed.parse::<IpAddr>()
        {
            return Self::Socket(SocketAddr::new(ip, default_port));
        }

        let host_port = if has_explicit_port(value) || value.contains(':') {
            value.to_string()
        } else {
            format!("{value}:{default_port}")
        };

        // A trailing root dot names the same host, so one server has one spelling.
        let host_port = match host_port.rsplit_once(':') {
            Some((host, port)) => format!("{}:{port}", host.strip_suffix('.').unwrap_or(host)),
            None => host_port,
        };

        Self::HostPort(host_port.to_ascii_lowercase())
    }
}

/// The stored and presentation form: `ip:port`, `[ipv6]:port`, or `host:port`.
impl fmt::Display for AddressTarget {
    /// Write the address target in its canonical form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(addr) => fmt::Display::fmt(addr, f),
            Self::HostPort(host_port) => f.pad(host_port),
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

    /// Return whether the SQL type can store this value.
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
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        self.to_string().encode_by_ref(buffer)
    }
}

/// The read half: the column holds the row form, so decoding never fails.
impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for AddressTarget
where
    &'r str: sqlx::Decode<'r, DB>,
{
    /// Read the row form.
    fn decode(value: <DB as sqlx::Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        Ok(Self::parse(
            <&str as sqlx::Decode<'r, DB>>::decode(value)?,
            DEFAULT_DNS_PORT,
        ))
    }
}

/// Replace a wildcard listen address, which is not connectable, with loopback
/// so it can be probed.
pub fn loopback_if_unspecified(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    }
}

/// Return whether text is `host[:port]`, `ip[:port]`, or `[ipv6][:port]`: LDH
/// labels (`_` allowed) and a numeric, non-zero port, as the resolver takes them.
pub fn is_address_target(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return addr.port() != 0;
    }
    if let Some((ip, rest)) = value
        .strip_prefix('[')
        .and_then(|value| value.split_once(']'))
    {
        return ip.parse::<IpAddr>().is_ok() && (rest.is_empty() || has_explicit_port(value));
    }

    match value.rsplit_once(':') {
        Some((host, _)) => has_explicit_port(value) && is_hostname(host),
        None => is_hostname(value),
    }
}

/// Return whether a hostname uses valid domain labels: each non-empty, at most
/// 63 bytes, letters, digits, hyphens or underscores, no hyphen at either end.
/// A resolver target is an LDH name with no escapes, so the dot is always a
/// label boundary here.
fn is_hostname(value: &str) -> bool {
    let name = value.strip_suffix('.').unwrap_or(value);
    !name.is_empty()
        && name.len() <= MAX_DOMAIN_LEN
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_DNS_LABEL_LEN
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Return whether an address target includes a valid explicit port.
fn has_explicit_port(value: &str) -> bool {
    if let Some((_, rest)) = value
        .strip_prefix('[')
        .and_then(|value| value.split_once(']'))
    {
        return rest.strip_prefix(':').is_some_and(is_valid_port);
    }

    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => is_valid_port(port),
        _ => false,
    }
}

/// Return whether text represents a nonzero 16-bit port.
fn is_valid_port(value: &str) -> bool {
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests;
