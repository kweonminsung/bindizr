//! RFC 3597 presentation and wire forms for ordinary types without a typed editor.

use super::{EncodeRdataError, ParseRecordValueError, Rdata, value::MAX_RECORD_RDATA};

/// Opaque RDATA whose presentation form declares its exact byte length.
pub struct OpaqueRecordValue(Vec<u8>);

impl OpaqueRecordValue {
    /// Decode RFC 3597, Section 5 generic text, checking its declared length.
    pub fn parse(value: &str) -> Result<Self, ParseRecordValueError> {
        let mut words = value.split_whitespace();
        if words.next() != Some(r"\#") {
            return Err(ParseRecordValueError::GenericRdata);
        }
        let len = words
            .next()
            .and_then(|word| word.parse::<usize>().ok())
            .ok_or(ParseRecordValueError::GenericRdata)?;
        if len > MAX_RECORD_RDATA {
            return Err(ParseRecordValueError::GenericRdataTooLong {
                max: MAX_RECORD_RDATA,
            });
        }
        let data = hex::decode(
            words
                .filter(|word| !matches!(*word, "(" | ")"))
                .collect::<String>(),
        )
        .map_err(|_| ParseRecordValueError::GenericRdata)?;
        if data.len() != len {
            return Err(ParseRecordValueError::GenericRdata);
        }
        Ok(Self(data))
    }

    /// Render the bytes without interpreting their contents.
    pub fn to_presentation(&self) -> String {
        format!(r"\# {} {}", self.0.len(), hex::encode_upper(&self.0))
            .trim_end()
            .to_string()
    }

    /// Encode the original octets, unchanged.
    pub fn to_rdata(&self) -> Result<Rdata, EncodeRdataError> {
        Rdata::new(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3597 requires exact lengths and preserves uninterpreted octets.
    #[test]
    fn generic_values_check_lengths_and_preserve_bytes() {
        for (value, bytes) in [
            (r"\# 0", vec![]),
            (r"\# 4 00ff C00c", vec![0, 255, 192, 12]),
        ] {
            let parsed = OpaqueRecordValue::parse(value).unwrap();
            assert_eq!(parsed.to_rdata().unwrap().as_bytes(), bytes);
            assert_eq!(
                OpaqueRecordValue::parse(&parsed.to_presentation())
                    .unwrap()
                    .to_rdata()
                    .unwrap()
                    .as_bytes(),
                bytes
            );
        }
        for value in [
            "",
            r"\#",
            r"\# 1",
            r"\# 0 00",
            r"\# 1 F",
            r"\# 1 GG",
            r"\# 65536",
        ] {
            assert!(OpaqueRecordValue::parse(value).is_err(), "{value}");
        }
    }
}
