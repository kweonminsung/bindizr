//! DS record values (RFC 4034, Section 5): a child zone's key digest, entered
//! by the operator at the delegation point.

use domain::base::iana::SecurityAlgorithm;

use crate::dns::dnssec::KeyTag;
use crate::dns::record::value::MAX_RECORD_RDATA;
use crate::dns::record::{EncodeRdataError, ParseRecordValueError, Rdata, value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecordValue {
    key_tag: KeyTag,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
}

impl DsRecordValue {
    /// Hold a DS computed from a key: its tag, algorithm number, digest type
    /// and the digest itself (RFC 4034, Section 5.1).
    pub fn new(key_tag: KeyTag, algorithm: u8, digest_type: u8, digest: Vec<u8>) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    /// Parse `<key tag> <algorithm> <digest type> <digest>`: the algorithm a
    /// number or mnemonic (RFC 4034, Section 5.3), the hex digest groupable as `dig` prints.
    pub fn parse(value: &str) -> Result<Self, ParseRecordValueError> {
        let mut fields = value.split_whitespace();
        let (Some(key_tag), Some(algorithm), Some(digest_type)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(ParseRecordValueError::DsShape {
                value: value.to_string(),
            });
        };
        // The IANA DNS Security Algorithm Numbers registry, as `domain` carries it.
        let algorithm = match SecurityAlgorithm::from_mnemonic(algorithm.as_bytes()) {
            Some(mnemonic) => mnemonic.to_int(),
            None => value::parse_u8_record_field("DS algorithm", algorithm)?,
        };

        Ok(Self {
            key_tag: KeyTag::from(value::parse_u16_record_field("DS key tag", key_tag)?),
            algorithm,
            digest_type: value::parse_u8_record_field("DS digest type", digest_type)?,
            digest: value::parse_hex_record_field("DS digest", fields)?,
        })
    }

    /// Validate the fields of this DS value.
    pub fn validate(&self) -> Result<(), ParseRecordValueError> {
        // Bounded so the record fits one transfer message beside its 4 fixed
        // RDATA bytes; enforced here so a stored row cannot poison an AXFR.
        const MAX_DIGEST: usize = MAX_RECORD_RDATA - 4;

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
            return Err(ParseRecordValueError::DsDigestLength {
                digest_type: self.digest_type,
                expected,
                len: self.digest.len(),
            });
        }

        if self.digest.len() > MAX_DIGEST {
            return Err(ParseRecordValueError::DsDigestTooLong {
                max: MAX_DIGEST,
                len: self.digest.len(),
            });
        }

        Ok(())
    }

    /// Return the digest octets.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Render the DS value in canonical text form.
    pub fn to_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.key_tag,
            self.algorithm,
            self.digest_type,
            hex::encode_upper(&self.digest)
        )
    }

    /// Encode the stored value as wire RDATA (RFC 4034, Section 5.1).
    pub fn to_rdata(&self) -> Result<Rdata, EncodeRdataError> {
        let mut rdata = Vec::with_capacity(4 + self.digest.len());
        rdata.extend_from_slice(&self.key_tag.as_u16().to_be_bytes());
        rdata.push(self.algorithm);
        rdata.push(self.digest_type);
        rdata.extend_from_slice(&self.digest);

        Rdata::new(rdata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `parse` joins spaced digest and canonicalizes hex case.
    #[test]
    fn parse_joins_spaced_digest_and_canonicalizes_hex_case() {
        let parsed = DsRecordValue::parse("34217 13 2 4b9b 6b07 3edd").unwrap();
        assert_eq!(parsed.to_text(), "34217 13 2 4B9B6B073EDD");
    }

    /// Verify that `parse` reads an algorithm mnemonic as its number (RFC
    /// 4034, Section 5.3) and renders the number.
    #[test]
    fn parse_accepts_algorithm_mnemonics() {
        for (mnemonic, number) in [
            ("ECDSAP256SHA256", 13),
            ("rsasha256", 8),
            ("Ed25519", 15),
            ("MLDSA44", 18),
        ] {
            let parsed = DsRecordValue::parse(&format!("34217 {mnemonic} 2 4B9B")).unwrap();
            assert_eq!(parsed.to_text(), format!("34217 {number} 2 4B9B"));
        }
        assert!(DsRecordValue::parse("34217 SHA256 2 4B9B").is_err());
    }

    /// Verify that `validate` pins the digest length per type.
    #[test]
    fn validate_pins_the_digest_length_per_type() {
        let short = DsRecordValue::parse("1 13 2 4B9B").unwrap();

        assert_eq!(
            short.validate(),
            Err(ParseRecordValueError::DsDigestLength {
                digest_type: 2,
                expected: 32,
                len: 2,
            })
        );

        // Unknown digest types carry no known length to enforce.
        assert!(
            DsRecordValue::parse("1 13 9 4B9B")
                .unwrap()
                .validate()
                .is_ok()
        );
    }

    /// Verify that `parse` rejects non hex and odd digests.
    #[test]
    fn parse_rejects_non_hex_and_odd_digests() {
        assert!(DsRecordValue::parse("1 13 2 XYZ1").is_err());
        assert!(DsRecordValue::parse("1 13 2 4B9").is_err());
        assert!(DsRecordValue::parse("1 13 2").is_err());
        // An even byte length with a multi-byte character once panicked by
        // slicing the digest mid-character; it must fail as non-hex.
        assert!(DsRecordValue::parse("1 13 2 4é4").is_err());
    }
}
