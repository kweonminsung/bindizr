use std::net::Ipv4Addr;

pub struct ARecordValue(Ipv4Addr);

impl ARecordValue {
    /// Parse and validate an IPv4 address for an A record.
    pub fn parse(value: &str) -> Result<Self, String> {
        value
            .parse::<Ipv4Addr>()
            .map(Self)
            .map_err(|_| format!("A record value must be a valid IPv4 address: {}", value))
    }

    /// Render the A value in canonical text form.
    pub fn canonical(&self) -> String {
        self.0.to_string()
    }
}
