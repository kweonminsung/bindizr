use std::net::Ipv6Addr;

pub struct AaaaRecordValue(Ipv6Addr);

impl AaaaRecordValue {
    pub fn parse(value: &str) -> Result<Self, String> {
        value
            .parse::<Ipv6Addr>()
            .map(Self)
            .map_err(|_| format!("AAAA record value must be a valid IPv6 address: {}", value))
    }

    pub fn canonical(&self) -> String {
        self.0.to_string()
    }
}
