use std::net::Ipv4Addr;

use crate::dns::record::{EncodeRdataError, ParseRecordValueError, Rdata};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ARecordValue(Ipv4Addr);

impl ARecordValue {
    /// Parse and validate an IPv4 address for an A record.
    pub fn parse(value: &str) -> Result<Self, ParseRecordValueError> {
        value
            .parse::<Ipv4Addr>()
            .map(Self)
            .map_err(|_| ParseRecordValueError::Ipv4 {
                value: value.to_string(),
            })
    }

    /// Render the A value in canonical text form.
    pub fn canonical(self) -> String {
        self.0.to_string()
    }

    /// Encode the address as its wire RDATA (RFC 1035, Section 3.4.1; RFC 3596, Section 2.2).
    pub fn to_rdata(self) -> Result<Rdata, EncodeRdataError> {
        Rdata::new(self.0.octets().to_vec())
    }
}
