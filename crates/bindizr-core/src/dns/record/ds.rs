//! DS record values (RFC 4034, Section 5): a child zone's key digest, entered
//! by the operator at the delegation point.

use super::value::parse_u16_record_field;

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
        let digest_hex: String = fields.collect();
        if digest_hex.is_empty() {
            return Err("DS record digest must not be empty".to_string());
        }

        Ok(Self {
            key_tag: parse_u16_record_field("DS key tag", key_tag)?,
            algorithm: parse_u8_field("DS algorithm", algorithm)?,
            digest_type: parse_u8_field("DS digest type", digest_type)?,
            digest: parse_hex_digest(&digest_hex)?,
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

    /// The wire fields of a stored value.
    pub(crate) fn wire_fields(self) -> (u16, u8, u8, Vec<u8>) {
        (self.key_tag, self.algorithm, self.digest_type, self.digest)
    }
}

fn parse_u8_field(field: &str, value: &str) -> Result<u8, String> {
    value
        .parse::<u8>()
        .map_err(|_| format!("{field} must be an unsigned 8-bit integer: {value}"))
}

fn parse_hex_digest(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("DS digest must be an even number of hex digits".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("DS digest must be hex: {hex}"))
        })
        .collect()
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
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
