use std::net::Ipv6Addr;

use crate::error::ServiceError;

pub(super) struct AaaaRecordValue(Ipv6Addr);

impl AaaaRecordValue {
    pub(super) fn parse(value: &str) -> Result<Self, ServiceError> {
        value.parse::<Ipv6Addr>().map(Self).map_err(|_| {
            ServiceError::BadRequest(format!(
                "AAAA record value must be a valid IPv6 address: {}",
                value
            ))
        })
    }

    pub(super) fn canonical(&self) -> String {
        self.0.to_string()
    }
}
