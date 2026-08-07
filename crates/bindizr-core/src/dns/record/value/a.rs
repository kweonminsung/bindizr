use std::net::Ipv4Addr;

pub(super) struct ARecordValue(Ipv4Addr);

impl ARecordValue {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        value
            .parse::<Ipv4Addr>()
            .map(Self)
            .map_err(|_| format!("A record value must be a valid IPv4 address: {}", value))
    }

    pub(super) fn canonical(&self) -> String {
        self.0.to_string()
    }
}
