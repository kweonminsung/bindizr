//! Negotiated response budgets, distinct from fixed field and TCP frame lengths.

use super::{EncodeMessageError, UDP_PAYLOAD_SIZE_WITHOUT_EDNS};
use crate::dns::DNS_TCP_MAX_SIZE;
use crate::dns::query::EDNS_UDP_PAYLOAD_SIZE;

/// The transport and final wire-size ceiling of one DNS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseLimit {
    udp_payload_size: Option<u16>,
}

impl ResponseLimit {
    /// The budget without EDNS (RFC 1035, Section 4.2.1).
    pub const UDP: Self = Self {
        udp_payload_size: Some(UDP_PAYLOAD_SIZE_WITHOUT_EDNS),
    };

    /// TCP and TLS messages use the two-octet frame length (RFC 1035, Section 4.2.2).
    pub const STREAM: Self = Self {
        udp_payload_size: None,
    };

    /// Clamp an EDNS advertisement to the server's supported UDP range (RFC 6891, Section 6.2.3).
    pub fn udp(advertised: u16) -> Self {
        Self {
            udp_payload_size: Some(
                advertised.clamp(UDP_PAYLOAD_SIZE_WITHOUT_EDNS, EDNS_UDP_PAYLOAD_SIZE),
            ),
        }
    }

    /// Whether overflow may use a UDP-specific response or truncation.
    pub fn is_udp(self) -> bool {
        self.udp_payload_size.is_some()
    }

    /// The ceiling after compression, OPT and TSIG have all been composed.
    pub fn max_len(self) -> usize {
        self.udp_payload_size.map_or(DNS_TCP_MAX_SIZE, usize::from)
    }

    /// Reject a completed message that cannot be sent within this budget.
    pub fn validate_len(self, len: usize) -> Result<(), EncodeMessageError> {
        if len > self.max_len() {
            return Err(EncodeMessageError::TooLarge {
                len,
                max_len: self.max_len(),
            });
        }

        Ok(())
    }
}
