use std::net::Ipv4Addr;

use crate::error::ServiceError;

pub(super) struct ARecordValue(Ipv4Addr);

impl ARecordValue {
    pub(super) fn parse(value: &str) -> Result<Self, ServiceError> {
        value.parse::<Ipv4Addr>().map(Self).map_err(|_| {
            ServiceError::BadRequest(format!(
                "A record value must be a valid IPv4 address: {}",
                value
            ))
        })
    }

    pub(super) fn canonical(&self) -> String {
        self.0.to_string()
    }
}
