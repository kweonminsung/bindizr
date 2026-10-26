//! WKS addresses, protocol numbers, and service bitmaps (RFC 1035, Section 3.4.2).

use std::net::Ipv4Addr;

use super::{EncodeRdataError, ParseRecordValueError, Rdata, value};

const WKS_PREFIX_LEN: usize = 5;
const MAX_SERVICE_BITMAP_LEN: usize = (u16::MAX as usize + 1) / 8;

/// One IPv4 address and protocol with a validated service bitmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WksRecordValue {
    address: Ipv4Addr,
    protocol: u8,
    services: Vec<u8>,
}

impl WksRecordValue {
    /// Parse `<IPv4> <protocol> [ports...]`, accepting TCP/UDP or a protocol number.
    pub fn parse(value: &str) -> Result<Self, ParseRecordValueError> {
        let mut words = value.split_whitespace();
        let (Some(address), Some(protocol)) = (words.next(), words.next()) else {
            return Err(ParseRecordValueError::WksShape);
        };
        let address = address
            .parse()
            .map_err(|_| ParseRecordValueError::WksAddress)?;
        let protocol = match protocol.to_ascii_uppercase().as_str() {
            "TCP" => 6,
            "UDP" => 17,
            _ => value::parse_u8_record_field("WKS protocol", protocol)?,
        };
        let mut services = Vec::new();

        for port in words.filter(|word| !matches!(*word, "(" | ")")) {
            let port = usize::from(value::parse_u16_record_field("WKS port", port)?);
            let index = port / 8;
            if services.len() <= index {
                services.resize(index + 1, 0);
            }
            services[index] |= 0x80 >> (port % 8);
        }

        Ok(Self {
            address,
            protocol,
            services,
        })
    }

    /// Decode WKS wire fields, rejecting bitmap shapes BIND cannot load.
    pub fn from_rdata(bytes: &[u8]) -> Result<Self, ParseRecordValueError> {
        if !(WKS_PREFIX_LEN..=WKS_PREFIX_LEN + MAX_SERVICE_BITMAP_LEN).contains(&bytes.len()) {
            return Err(ParseRecordValueError::WksRdata);
        }

        // BIND rejects trailing zero bitmap bytes, which would prevent zone loading.
        if bytes.len() > WKS_PREFIX_LEN && bytes.last() == Some(&0) {
            return Err(ParseRecordValueError::WksBitmapPadding);
        }

        Ok(Self {
            address: Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            protocol: bytes[4],
            services: bytes[WKS_PREFIX_LEN..].to_vec(),
        })
    }

    /// The identity used when an UPDATE replaces a WKS value (RFC 2136, Section 1.1.5).
    pub fn address_and_protocol(&self) -> (Ipv4Addr, u8) {
        (self.address, self.protocol)
    }

    /// Render the protocol and distinct ports as ordered numeric fields.
    pub fn canonical(&self) -> String {
        let mut value = format!("{} {}", self.address, self.protocol);

        for (index, byte) in self.services.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    value.push_str(&format!(" {}", index * 8 + bit));
                }
            }
        }

        value
    }

    /// Encode the address, protocol, and original service bitmap.
    pub fn to_rdata(&self) -> Result<Rdata, EncodeRdataError> {
        Rdata::new(self.wire_bytes())
    }

    /// Join the fixed fields and bitmap without altering their octets.
    fn wire_bytes(&self) -> Vec<u8> {
        let mut bytes = self.address.octets().to_vec();
        bytes.push(self.protocol);
        bytes.extend_from_slice(&self.services);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check bitmap boundaries, duplicate ports, and port 65535.
    #[test]
    fn parse_encodes_port_bitmap_boundaries() {
        let parsed = WksRecordValue::parse("192.0.2.1 TCP ( 65535 8 7 0 8 )").unwrap();
        let bytes = parsed.to_rdata().unwrap();

        assert_eq!(&bytes.as_bytes()[..7], &[192, 0, 2, 1, 6, 0x81, 0x80]);
        assert_eq!(
            bytes.as_bytes().len(),
            WKS_PREFIX_LEN + MAX_SERVICE_BITMAP_LEN
        );
        assert_eq!(bytes.as_bytes().last(), Some(&1));
        assert_eq!(parsed.canonical(), "192.0.2.1 6 0 7 8 65535");
        assert_eq!(WksRecordValue::parse(&parsed.canonical()).unwrap(), parsed);
    }

    /// Preserve empty bitmaps and protocol numbers across wire/text round trips.
    #[test]
    fn wire_roundtrip_preserves_empty_and_nonempty_bitmaps() {
        for bytes in [
            vec![192, 0, 2, 1, 255],
            vec![192, 0, 2, 1, 17, 1],
            vec![192, 0, 2, 1, 6, 0x80, 1],
        ] {
            let parsed = WksRecordValue::from_rdata(&bytes).unwrap();

            assert_eq!(
                WksRecordValue::parse(&parsed.canonical())
                    .unwrap()
                    .to_rdata()
                    .unwrap()
                    .as_bytes(),
                bytes
            );
        }

        assert_eq!(
            WksRecordValue::parse("192.0.2.1 UDP 53")
                .unwrap()
                .address_and_protocol(),
            (Ipv4Addr::new(192, 0, 2, 1), 17)
        );
    }

    /// Reject malformed addresses, integer overflow, and invalid WKS wire shapes.
    #[test]
    fn parse_rejects_invalid_addresses_protocols_ports_and_lengths() {
        for value in [
            "",
            "192.0.2.1",
            "::1 TCP 80",
            "192.0.2.1 256 80",
            "192.0.2.1 TCP 65536",
            "192.0.2.1 TCP -1",
            "192.0.2.1 TCP http",
            r"\# 4 C0000201",
            r"\# 5 C000020106FF",
            r"\# 6 C000020106GG",
        ] {
            assert!(WksRecordValue::parse(value).is_err(), "{value}");
        }

        assert!(WksRecordValue::from_rdata(&[0; 4]).is_err());
        assert_eq!(
            WksRecordValue::from_rdata(&[192, 0, 2, 1, 6, 0x80, 0]),
            Err(ParseRecordValueError::WksBitmapPadding)
        );
        assert!(
            WksRecordValue::from_rdata(&vec![0; WKS_PREFIX_LEN + MAX_SERVICE_BITMAP_LEN + 1])
                .is_err()
        );
    }
}
