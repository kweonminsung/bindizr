//! DS record values (RFC 4034, Section 5): a child zone's key digest, entered
//! by the operator at the delegation point.

use super::{
    Rdata,
    value::{hex_upper, parse_hex_record_field, parse_u8_record_field, parse_u16_record_field},
};

pub(crate) struct DsRecordValue {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
}

impl DsRecordValue {
    /// The value is `<key tag> <algorithm> <digest type> <digest>`; the hex
    /// digest may be split into whitespace-separated groups, as `dig` prints.
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let mut fields = value.split_whitespace();
        let (Some(key_tag), Some(algorithm), Some(digest_type)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(format!(
                "DS record value must be '<key tag> <algorithm> <digest type> <digest>': {value}"
            ));
        };
        Ok(Self {
            key_tag: parse_u16_record_field("DS key tag", key_tag)?,
            algorithm: parse_u8_record_field("DS algorithm", algorithm)?,
            digest_type: parse_u8_record_field("DS digest type", digest_type)?,
            digest: parse_hex_record_field("DS digest", fields)?,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        // Digest lengths are fixed per type (RFC 4509 for SHA-256); a wrong
        // length is a broken delegation, not a serveable record.
        let expected = match self.digest_type {
            1 => Some(20),
            2 => Some(32),
            4 => Some(48),
            _ => None,
        };
        if let Some(expected) = expected
            && self.digest.len() != expected
        {
            return Err(format!(
                "DS digest type {} takes a {}-byte digest, got {}",
                self.digest_type,
                expected,
                self.digest.len()
            ));
        }
        Ok(())
    }

    pub(crate) fn canonical(&self) -> String {
        format!(
            "{} {} {} {}",
            self.key_tag,
            self.algorithm,
            self.digest_type,
            hex_upper(&self.digest)
        )
    }

    /// The wire-format RDATA of a stored value (RFC 4034, Section 5.1).
    pub(crate) fn to_rdata(&self) -> Result<Rdata, String> {
        let mut rdata = Vec::with_capacity(4 + self.digest.len());
        rdata.extend_from_slice(&self.key_tag.to_be_bytes());
        rdata.push(self.algorithm);
        rdata.push(self.digest_type);
        rdata.extend_from_slice(&self.digest);
        Rdata::new(rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::DsRecordValue;

    #[test]
    fn parse_joins_spaced_digest_and_canonicalizes_hex_case() {
        let parsed = DsRecordValue::parse("34217 13 2 4b9b 6b07 3edd").unwrap();
        assert_eq!(parsed.canonical(), "34217 13 2 4B9B6B073EDD");
    }

    #[test]
    fn validate_pins_the_digest_length_per_type() {
        let short = DsRecordValue::parse("1 13 2 4B9B").unwrap();
        assert!(short.validate().unwrap_err().contains("32-byte"));
        // Unknown digest types carry no known length to enforce.
        assert!(
            DsRecordValue::parse("1 13 9 4B9B")
                .unwrap()
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn parse_rejects_non_hex_and_odd_digests() {
        assert!(DsRecordValue::parse("1 13 2 XYZ1").is_err());
        assert!(DsRecordValue::parse("1 13 2 4B9").is_err());
        assert!(DsRecordValue::parse("1 13 2").is_err());
    }
}
