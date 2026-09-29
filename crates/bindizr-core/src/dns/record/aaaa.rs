use std::net::Ipv6Addr;

use super::ParseRecordValueError;

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
    pub fn canonical(&self) -> String {
        self.0.to_string()
    }
}
