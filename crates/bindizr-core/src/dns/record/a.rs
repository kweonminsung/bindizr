use std::net::Ipv4Addr;

use super::ParseRecordValueError;

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
    pub fn canonical(&self) -> String {
        self.0.to_string()
    }
}
