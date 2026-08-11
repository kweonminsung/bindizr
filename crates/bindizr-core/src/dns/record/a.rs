use std::net::Ipv4Addr;

pub(crate) struct ARecordValue(Ipv4Addr);

impl ARecordValue {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        value
            .parse::<Ipv4Addr>()
            .map(Self)
            .map_err(|_| format!("A record value must be a valid IPv4 address: {}", value))
    }

    pub(crate) fn canonical(&self) -> String {
        self.0.to_string()
    }
}
