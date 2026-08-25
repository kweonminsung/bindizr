//! TLSA record values (RFC 6698): DANE certificate associations, verifiable
//! only from a signed zone.

use super::{
    Rdata,
    value::{MAX_RECORD_RDATA, hex_upper, parse_hex_record_field, parse_u8_record_field},
};

pub(crate) struct TlsaRecordValue {
    cert_usage: u8,
    selector: u8,
    matching_type: u8,
    cert_data: Vec<u8>,
}

impl TlsaRecordValue {
    /// The value is `<usage> <selector> <matching type> <certificate data>`;
    /// the hex data may be split into whitespace-separated groups.
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let mut fields = value.split_whitespace();
        let (Some(cert_usage), Some(selector), Some(matching_type)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(format!(
                "TLSA record value must be '<usage> <selector> <matching type> <certificate data>': {value}"
            ));
        };
        Ok(Self {
            cert_usage: parse_u8_record_field("TLSA certificate usage", cert_usage)?,
            selector: parse_u8_record_field("TLSA selector", selector)?,
            matching_type: parse_u8_record_field("TLSA matching type", matching_type)?,
            cert_data: parse_hex_record_field("TLSA certificate data", fields)?,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        // Digest lengths are fixed per matching type; type 0 is a full
        // certificate or SPKI and takes any length.
        let expected = match self.matching_type {
            1 => Some(32),
            2 => Some(64),
            _ => None,
        };
        if let Some(expected) = expected
            && self.cert_data.len() != expected
        {
            return Err(format!(
                "TLSA matching type {} takes {}-byte certificate data, got {}",
                self.matching_type,
                expected,
                self.cert_data.len()
            ));
        }
        // Bounded so the record fits one transfer message beside its 3 fixed
        // RDATA bytes; enforced here so a stored row cannot poison an AXFR.
        const MAX_CERT_DATA: usize = MAX_RECORD_RDATA - 3;
        if self.cert_data.len() > MAX_CERT_DATA {
            return Err(format!(
                "TLSA certificate data must be at most {MAX_CERT_DATA} bytes, got {}",
                self.cert_data.len()
            ));
        }
        Ok(())
    }

    pub(crate) fn canonical(&self) -> String {
        format!(
            "{} {} {} {}",
            self.cert_usage,
            self.selector,
            self.matching_type,
            hex_upper(&self.cert_data)
        )
    }

    /// The wire-format RDATA of a stored value (RFC 6698, Section 2.1).
    pub(crate) fn to_rdata(&self) -> Result<Rdata, String> {
        let mut rdata = Vec::with_capacity(3 + self.cert_data.len());
        rdata.push(self.cert_usage);
        rdata.push(self.selector);
        rdata.push(self.matching_type);
        rdata.extend_from_slice(&self.cert_data);
        Rdata::new(rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::TlsaRecordValue;

    #[test]
    fn parse_joins_spaced_hex_and_canonicalizes() {
        let parsed = TlsaRecordValue::parse(
            "3 1 1 4b9b6b073edd97fe1a7b19871ee93be250e49b2d9466e661a22c74c426ace383",
        )
        .unwrap();
        assert_eq!(
            parsed.canonical(),
            "3 1 1 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D9466E661A22C74C426ACE383"
        );
    }

    #[test]
    fn validate_pins_digest_lengths_but_not_full_certificates() {
        let short = TlsaRecordValue::parse("3 1 1 4B9B").unwrap();
        assert!(short.validate().unwrap_err().contains("32-byte"));
        // Matching type 0 carries the full certificate at any length.
        assert!(
            TlsaRecordValue::parse("3 0 0 4B9B")
                .unwrap()
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_caps_full_certificates_below_the_message_limit() {
        let at_limit = format!("3 0 0 {}", "AB".repeat(64_996));
        assert!(
            TlsaRecordValue::parse(&at_limit)
                .unwrap()
                .validate()
                .is_ok()
        );
        let oversized = format!("3 0 0 {}", "AB".repeat(64_997));
        let err = TlsaRecordValue::parse(&oversized).unwrap().validate();
        assert!(err.unwrap_err().contains("64996"));
    }
}
