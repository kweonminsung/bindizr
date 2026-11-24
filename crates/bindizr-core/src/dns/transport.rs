//! Transports supported by the DNS front end.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Unsupported text for a DNS transport.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported DNS transport '{value}'")]
pub struct ParseDnsTransportError {
    pub value: String,
}

/// Transport carrying a DNS message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DnsTransport {
    Udp,
    Tcp,
    Tls,
}

impl DnsTransport {
    /// Every transport, for the metric series registered up front.
    pub const ALL: [Self; 3] = [Self::Udp, Self::Tcp, Self::Tls];

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }
}

impl fmt::Display for DnsTransport {
    /// Write the transport as its DNS mnemonic.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
        })
    }
}

impl FromStr for DnsTransport {
    type Err = ParseDnsTransportError;

    /// Parse a transport from its text representation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "tls" => Ok(Self::Tls),
            _ => Err(ParseDnsTransportError {
                value: value.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for DnsTransport {
    type Error = ParseDnsTransportError;

    /// Validate and convert the stored value into a transport.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Verify that `DnsTransport` has one spelling across `as_str`, serde, and `FromStr`.
    #[test]
    fn dns_transport_spells_itself_once() {
        for value in [DnsTransport::Udp, DnsTransport::Tcp, DnsTransport::Tls] {
            assert_eq!(serde_json::to_value(value).unwrap(), json!(value.as_str()));
            assert_eq!(
                serde_json::from_value::<DnsTransport>(json!(value.as_str())).unwrap(),
                value
            );
            assert_eq!(value.as_str().parse::<DnsTransport>().unwrap(), value);
        }
    }
}
