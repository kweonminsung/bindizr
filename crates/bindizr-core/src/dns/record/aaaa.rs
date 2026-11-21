use std::net::Ipv6Addr;

use crate::dns::record::{EncodeRdataError, ParseRecordValueError, Rdata};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AaaaRecordValue(Ipv6Addr);

impl AaaaRecordValue {
    /// Parse and validate a AAAA record value.
    pub fn parse(value: &str) -> Result<Self, ParseRecordValueError> {
        value
            .parse::<Ipv6Addr>()
            .map(Self)
            .map_err(|_| ParseRecordValueError::Ipv6 {
                value: value.to_string(),
            })
    }

    /// Render the AAAA value in canonical text form.
    pub fn canonical(self) -> String {
        self.0.to_string()
    }

    /// Encode the address as its wire RDATA (RFC 1035, Section 3.4.1; RFC 3596, Section 2.2).
    pub fn to_rdata(self) -> Result<Rdata, EncodeRdataError> {
        Rdata::new(self.0.octets().to_vec())
    }
}
