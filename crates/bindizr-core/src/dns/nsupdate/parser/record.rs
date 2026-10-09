//! The wire fields of a prerequisite or update record, its update-section
//! shape, and decoding of its RDATA without losing compression offsets.

use domain::{
    base::{
        iana::{Class, Rtype},
        name::ParsedName,
    },
    dep::octseq::parse::Parser,
    rdata::{A, Aaaa, Mx, Srv, Txt},
};
use thiserror::Error;

use super::{ParseUpdateError, to_presentation_name};
use crate::{
    dns::record::{NaptrRecordValue, Rdata, TxtRecordValue},
    model::record::RecordType,
};

/// One record from the prerequisite or update section. `rdata_start` locates the
/// rdata in the original message so compressed names inside it can be decoded
/// lazily by the update flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRecord {
    pub name: String,
    pub record_type: Rtype,
    pub class: Class,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub rdata_start: usize,
}

/// A wire shape the IN-zone update section cannot carry (RFC 2136,
/// Section 3.4.1). This is independent of whether the RR can change stored data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UpdateShapeError {
    #[error("unsupported update class: {class}")]
    Class { class: Class },
    #[error("type {record_type} is not permitted in this update")]
    RecordType { record_type: Rtype },
    #[error("delete update TTL must be 0")]
    NonzeroTtl,
    #[error("ANY-class delete must have empty rdata")]
    AnyClassRdata,
    #[error("NONE-class delete must specify rdata")]
    NoneClassNoRdata,
}

impl UpdateRecord {
    /// Check the class, type, TTL and RDATA shape before interpreting an
    /// IN-zone update (RFC 2136, Section 3.4.1.2).
    pub fn validate_update_shape(&self) -> Result<(), UpdateShapeError> {
        if !matches!(self.class, Class::IN | Class::ANY | Class::NONE) {
            return Err(UpdateShapeError::Class { class: self.class });
        }
        // RFC 6895, Section 3.1 reserves 128-255 for query/meta types;
        // OPT is the meta type outside that range. ANY is permitted only
        // as the CLASS ANY whole-name delete (RFC 2136, Section 2.5.3).
        let delete_name = self.class == Class::ANY && self.record_type == Rtype::ANY;
        if !delete_name && matches!(self.record_type.to_int(), 0 | 41 | 128..=255 | 65535) {
            return Err(UpdateShapeError::RecordType {
                record_type: self.record_type,
            });
        }
        if self.class != Class::IN && self.ttl != 0 {
            return Err(UpdateShapeError::NonzeroTtl);
        }
        match self.class {
            Class::ANY if !self.rdata.is_empty() => Err(UpdateShapeError::AnyClassRdata),
            Class::NONE if self.rdata.is_empty() => Err(UpdateShapeError::NoneClassNoRdata),
            _ => Ok(()),
        }
    }

    /// Decode prerequisite RDATA for comparison, resolving names in `message`.
    pub fn to_rdata(&self, message: &[u8]) -> Result<Rdata, ParseUpdateError> {
        Ok(Rdata::parse_canonical(
            self.record_type,
            message,
            self.rdata_start,
            self.rdata.len(),
        )?)
    }

    /// Decode an update record's wire data into its typed value.
    fn parse_rdata<'a, T>(
        &self,
        message: &'a [u8],
        what: &str,
        parse: impl FnOnce(&mut Parser<'a, [u8]>) -> Option<T>,
    ) -> Result<T, ParseUpdateError> {
        let refused = || ParseUpdateError::Rdata {
            record_type: what.to_string(),
        };

        // Compression pointers address the whole message, not the RDATA slice.
        let mut parser = Parser::from_ref(message);
        parser.advance(self.rdata_start).map_err(|_| refused())?;
        let value = parse(&mut parser).ok_or_else(refused)?;

        // A type parser must consume exactly RDLENGTH, without borrowing the next record.
        if parser.pos() != self.rdata_start + self.rdata.len() {
            return Err(refused());
        }

        Ok(value)
    }

    /// Decode this record into stored columns. `message` must be the original
    /// UPDATE message: compressed RDATA names refer to offsets within it.
    pub fn to_record_value(
        &self,
        message: &[u8],
    ) -> Result<(RecordType, String, Option<i32>), ParseUpdateError> {
        match RecordType::try_from(self.record_type)? {
            RecordType::A => {
                let data = self.parse_rdata(message, "A", |parser| A::parse(parser).ok())?;
                Ok((RecordType::A, data.addr().to_string(), None))
            }
            RecordType::Aaaa => {
                let data = self.parse_rdata(message, "AAAA", |parser| Aaaa::parse(parser).ok())?;
                Ok((RecordType::Aaaa, data.addr().to_string(), None))
            }
            record_type @ (RecordType::Cname
            | RecordType::Dname
            | RecordType::Ns
            | RecordType::Ptr) => {
                let name = self.parse_rdata(message, record_type.as_str(), |parser| {
                    ParsedName::parse(parser).ok()
                })?;
                let value =
                    to_presentation_name(&name).map_err(|e| ParseUpdateError::RdataName {
                        record_type: record_type.as_str().to_string(),
                        source: Box::new(e),
                    })?;
                Ok((record_type, value, None))
            }
            RecordType::Txt => {
                let data = Txt::from_octets(self.rdata.as_slice()).map_err(|e| {
                    ParseUpdateError::TxtRdata {
                        reason: e.to_string(),
                    }
                })?;
                // TXT values must be valid UTF-8 (a project-wide rule), so reject
                // non-UTF-8 character-strings even though the wire allows them.
                for charstr in data.iter_charstrs() {
                    if std::str::from_utf8(charstr.as_slice()).is_err() {
                        return Err(ParseUpdateError::Rdata {
                            record_type: "TXT".to_string(),
                        });
                    }
                }
                let value = TxtRecordValue::from_rdata(&self.rdata)
                    .map_err(ParseUpdateError::TxtValue)?
                    .to_presentation();
                Ok((RecordType::Txt, value, None))
            }
            RecordType::Caa => {
                let data = self.parse_rdata(message, "CAA", |parser| {
                    domain::rdata::Caa::parse(parser).ok()
                })?;
                Ok((RecordType::Caa, data.to_string(), None))
            }
            RecordType::Ds => {
                let data = self.parse_rdata(message, "DS", |parser| {
                    domain::rdata::Ds::parse(parser).ok()
                })?;
                Ok((RecordType::Ds, data.to_string(), None))
            }
            RecordType::Naptr => {
                let data = self.parse_rdata(message, "NAPTR", |parser| {
                    domain::rdata::Naptr::parse(parser).ok()
                })?;
                let replacement = to_presentation_name(data.replacement()).map_err(|e| {
                    ParseUpdateError::RdataName {
                        record_type: "NAPTR".to_string(),
                        source: Box::new(e),
                    }
                })?;
                let value = NaptrRecordValue::from_wire(
                    data.order(),
                    data.preference(),
                    data.flags().as_slice(),
                    data.services().as_slice(),
                    data.regexp().as_slice(),
                    &replacement,
                )?
                .canonical();
                Ok((RecordType::Naptr, value, None))
            }
            RecordType::Sshfp => {
                let data = self.parse_rdata(message, "SSHFP", |parser| {
                    domain::rdata::Sshfp::parse(parser).ok()
                })?;
                Ok((RecordType::Sshfp, data.to_string(), None))
            }
            RecordType::Tlsa => {
                let data = self.parse_rdata(message, "TLSA", |parser| {
                    domain::rdata::Tlsa::parse(parser).ok()
                })?;
                Ok((RecordType::Tlsa, data.to_string(), None))
            }
            RecordType::Mx => {
                let data = self.parse_rdata(message, "MX", |parser| Mx::parse(parser).ok())?;
                let host = to_presentation_name(data.exchange()).map_err(|e| {
                    ParseUpdateError::RdataName {
                        record_type: "MX".to_string(),
                        source: Box::new(e),
                    }
                })?;
                Ok((RecordType::Mx, host, Some(i32::from(data.preference()))))
            }
            RecordType::Srv => {
                let data = self.parse_rdata(message, "SRV", |parser| Srv::parse(parser).ok())?;
                let target = to_presentation_name(data.target()).map_err(|e| {
                    ParseUpdateError::RdataName {
                        record_type: "SRV".to_string(),
                        source: Box::new(e),
                    }
                })?;
                // Priority lives in its own column, so the value holds the rest.
                Ok((
                    RecordType::Srv,
                    format!("{} {} {}", data.weight(), data.port(), target),
                    Some(i32::from(data.priority())),
                ))
            }
        }
    }
}
