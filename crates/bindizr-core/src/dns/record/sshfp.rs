//! SSHFP record values (RFC 4255): SSH host-key fingerprints, verifiable
//! only from a signed zone.

use super::{
    Rdata,
    value::{MAX_RECORD_RDATA, hex_upper, parse_hex_record_field, parse_u8_record_field},
};

pub struct SshfpRecordValue {
    algorithm: u8,
    fingerprint_type: u8,
    fingerprint: Vec<u8>,
}

impl SshfpRecordValue {
    /// The value is `<algorithm> <fingerprint type> <fingerprint>`; the hex
    /// fingerprint may be split into whitespace-separated groups.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut fields = value.split_whitespace();
        let (Some(algorithm), Some(fingerprint_type)) = (fields.next(), fields.next()) else {
            return Err(format!(
                "SSHFP record value must be '<algorithm> <fingerprint type> <fingerprint>': {value}"
            ));
        };
        Ok(Self {
            algorithm: parse_u8_record_field("SSHFP algorithm", algorithm)?,
            fingerprint_type: parse_u8_record_field("SSHFP fingerprint type", fingerprint_type)?,
            fingerprint: parse_hex_record_field("SSHFP fingerprint", fields)?,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        // Fingerprint lengths are fixed per type: SHA-1 and SHA-256.
        let expected = match self.fingerprint_type {
            1 => Some(20),
            2 => Some(32),
            _ => None,
        };
        if let Some(expected) = expected
            && self.fingerprint.len() != expected
        {
            return Err(format!(
                "SSHFP fingerprint type {} takes a {}-byte fingerprint, got {}",
                self.fingerprint_type,
                expected,
                self.fingerprint.len()
            ));
        }
        // Bounded so the record fits one transfer message beside its 2 fixed
        // RDATA bytes; enforced here so a stored row cannot poison an AXFR.
        const MAX_FINGERPRINT: usize = MAX_RECORD_RDATA - 2;
        if self.fingerprint.len() > MAX_FINGERPRINT {
            return Err(format!(
                "SSHFP fingerprint must be at most {MAX_FINGERPRINT} bytes, got {}",
                self.fingerprint.len()
            ));
        }
        Ok(())
    }

    pub fn canonical(&self) -> String {
        format!(
            "{} {} {}",
            self.algorithm,
            self.fingerprint_type,
            hex_upper(&self.fingerprint)
        )
    }

    /// The wire-format RDATA of a stored value (RFC 4255, Section 3.1).
    pub fn to_rdata(&self) -> Result<Rdata, String> {
        let mut rdata = Vec::with_capacity(2 + self.fingerprint.len());
        rdata.push(self.algorithm);
        rdata.push(self.fingerprint_type);
        rdata.extend_from_slice(&self.fingerprint);
        Rdata::new(rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::SshfpRecordValue;

    #[test]
    fn parse_drops_rfc1035_parens_around_the_fingerprint() {
        // The form `domain`'s Display emits, fed back by nsupdate and import.
        let parsed = SshfpRecordValue::parse(&format!("4 2 ( {} )", "ab".repeat(32))).unwrap();
        assert_eq!(parsed.canonical(), format!("4 2 {}", "AB".repeat(32)));
    }

    #[test]
    fn parse_joins_spaced_hex_and_canonicalizes() {
        let parsed =
            SshfpRecordValue::parse("4 1 4b9b 6b07 3edd 97fe 1a7b 1987 1ee9 3be2 50e4 9b2d")
                .unwrap();
        assert_eq!(
            parsed.canonical(),
            "4 1 4B9B6B073EDD97FE1A7B19871EE93BE250E49B2D"
        );
    }

    #[test]
    fn validate_pins_the_fingerprint_length_per_type() {
        let short = SshfpRecordValue::parse("4 2 4B9B").unwrap();
        assert!(short.validate().unwrap_err().contains("32-byte"));
        assert!(
            SshfpRecordValue::parse("4 9 4B9B")
                .unwrap()
                .validate()
                .is_ok()
        );
    }
}
