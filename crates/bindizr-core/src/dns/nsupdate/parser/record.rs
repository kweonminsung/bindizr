//! The wire fields of a prerequisite or update record, its update-section
//! shape, and decoding of its RDATA without losing compression offsets.

use domain::base::iana::{Class, Rtype};
use domain::base::name::ParsedName;
use domain::dep::octseq::parse::Parser;
use domain::rdata::{A, Aaaa, Caa, Ds, Mx, Naptr, Soa, Srv, Sshfp, Tlsa};
use thiserror::Error;

use crate::dns::nsupdate::parser;
use crate::dns::nsupdate::parser::ParseUpdateError;
use crate::dns::record::{NaptrRecordValue, Rdata, SoaRecordValue, TxtRecordValue, WksRecordValue};
use crate::model::record::RecordType;

/// A prerequisite or update record with an RDATA offset into the original message.
/// The offset lets the update flow decode compressed names lazily.
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
/// Section 3.4.1). This is independent of whether the record can change stored data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ValidateUpdateShapeError {
    #[error("unsupported update class: {class}")]
    Class { class: Class },
    #[error("type {record_type} is not permitted in this update")]
    RecordType { record_type: Rtype },
    #[error("delete update TTL must be 0")]
    NonzeroTtl,
    #[error("ANY-class delete must have empty rdata")]
    AnyClassRdata,
}

impl UpdateRecord {
    /// Check the class, type, TTL and RDATA shape before interpreting an
    /// IN-zone update (RFC 2136, Section 3.4.1.2).
    pub fn validate_update_shape(&self) -> Result<(), ValidateUpdateShapeError> {
        if !matches!(self.class, Class::IN | Class::ANY | Class::NONE) {
            return Err(ValidateUpdateShapeError::Class { class: self.class });
        }

        // RFC 6895, Section 3.1 reserves 128-255 for query/meta types;
        // OPT is the meta type outside that range. ANY is permitted only
        // as the CLASS ANY whole-name delete (RFC 2136, Section 2.5.3).
        let delete_name = self.class == Class::ANY && self.record_type == Rtype::ANY;

        if !delete_name && matches!(self.record_type.to_int(), 0 | 41 | 128..=255 | 65535) {
            return Err(ValidateUpdateShapeError::RecordType {
                record_type: self.record_type,
            });
        }
        if self.class != Class::IN && self.ttl != 0 {
            return Err(ValidateUpdateShapeError::NonzeroTtl);
        }

        if self.class == Class::ANY && !self.rdata.is_empty() {
            return Err(ValidateUpdateShapeError::AnyClassRdata);
        }

        Ok(())
    }

    /// Decode the RDATA, resolving names in `message`: for a prerequisite's
    /// comparison and an update record's shape check alike.
    pub fn to_rdata(&self, message: &[u8]) -> Result<Rdata, ParseUpdateError> {
        if self.record_type == Rtype::WKS {
            WksRecordValue::from_rdata(&self.rdata)?;
        }

        Ok(Rdata::parse_canonical(
            self.record_type,
            message,
            self.rdata_start,
            self.rdata.len(),
        )?)
    }

    /// Decode SOA fields without applying zone storage policy.
    pub fn to_soa_value(&self, message: &[u8]) -> Result<SoaRecordValue<String>, ParseUpdateError> {
        let data = self.parse_rdata(message, "SOA", |parser| Soa::parse(parser).ok())?;
        Ok(SoaRecordValue {
            mname: parser::to_presentation_name(data.mname()),
            rname: parser::to_presentation_name(data.rname()),
            serial: data.serial().into_int(),
            refresh: data.refresh().as_secs(),
            retry: data.retry().as_secs(),
            expire: data.expire().as_secs(),
            minimum: data.minimum().as_secs(),
        })
    }

    /// Decode an update record's wire data into its typed value.
    fn parse_rdata<'a, T>(
        &self,
        message: &'a [u8],
        record_type: &'static str,
        parse: impl FnOnce(&mut Parser<'a, [u8]>) -> Option<T>,
    ) -> Result<T, ParseUpdateError> {
        let refused = || ParseUpdateError::Rdata { record_type };

        // RDLENGTH bounds the value while compression retains message offsets
        // (RFC 1035, Sections 4.1.3–4.1.4).
        let mut parser = Parser::from_ref(message);
        parser.advance(self.rdata_start).map_err(|_| refused())?;
        let mut rdata = parser
            .parse_parser(self.rdata.len())
            .map_err(|_| refused())?;
        let value = parse(&mut rdata).ok_or_else(refused)?;

        if rdata.remaining() != 0 {
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
            RecordType::Wks => Ok((
                RecordType::Wks,
                WksRecordValue::from_rdata(&self.rdata)?.canonical(),
                None,
            )),
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
                let value = parser::to_presentation_name(&name);

                Ok((record_type, value, None))
            }
            RecordType::Txt => {
                let value = TxtRecordValue::from_rdata(&self.rdata)?.to_presentation();
                Ok((RecordType::Txt, value, None))
            }
            RecordType::Caa => {
                let data = self.parse_rdata(message, "CAA", |parser| Caa::parse(parser).ok())?;
                Ok((RecordType::Caa, data.to_string(), None))
            }
            RecordType::Ds => {
                let data = self.parse_rdata(message, "DS", |parser| Ds::parse(parser).ok())?;
                Ok((RecordType::Ds, data.to_string(), None))
            }
            RecordType::Naptr => {
                let data =
                    self.parse_rdata(message, "NAPTR", |parser| Naptr::parse(parser).ok())?;
                let replacement = parser::to_presentation_name(data.replacement());
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
                let data =
                    self.parse_rdata(message, "SSHFP", |parser| Sshfp::parse(parser).ok())?;
                Ok((RecordType::Sshfp, data.to_string(), None))
            }
            RecordType::Tlsa => {
                let data = self.parse_rdata(message, "TLSA", |parser| Tlsa::parse(parser).ok())?;
                Ok((RecordType::Tlsa, data.to_string(), None))
            }
            RecordType::Mx => {
                let data = self.parse_rdata(message, "MX", |parser| Mx::parse(parser).ok())?;
                let host = parser::to_presentation_name(data.exchange());

                Ok((RecordType::Mx, host, Some(i32::from(data.preference()))))
            }
            RecordType::Srv => {
                let data = self.parse_rdata(message, "SRV", |parser| Srv::parse(parser).ok())?;
                let target = parser::to_presentation_name(data.target());

                // Priority lives in its own column, so the value holds the rest.
                Ok((
                    RecordType::Srv,
                    format!("{} {} {target}", data.weight(), data.port()),
                    Some(i32::from(data.priority())),
                ))
            }
        }
    }
}
