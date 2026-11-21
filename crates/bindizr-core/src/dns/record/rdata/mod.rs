//! [`Rdata::from_columns`] maps stored columns to wire RDATA for both
//! XFR and DNSSEC, keeping transferred bytes identical to signed bytes.

mod canonical;

use base64::Engine;
use base64::engine::general_purpose;
pub use canonical::ParseRdataError;
use domain::base::iana::Rtype;
use domain::base::name::ParsedName;
use domain::base::rdata::ParseRecordData;
use domain::dep::octseq::parse::Parser;
use domain::rdata::AllRecordData;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;

use crate::dns::name;
use crate::dns::name::EncodeNameError;
use crate::dns::record::{
    ARecordValue, AaaaRecordValue, CaaRecordValue, DsRecordValue, MxRecordValue, NaptrRecordValue,
    ParseMailboxError, ParseRecordValueError, SrvRecordValue, SshfpRecordValue, TlsaRecordValue,
    TxtRecordValue, WksRecordValue,
};
use crate::model::dnssec_record::DnssecRecordType;
use crate::model::record::RecordType;

/// Why stored columns did not become wire RDATA: a value or name that does
/// not encode, or an encoding past the RDLENGTH limit.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeRdataError {
    #[error("RDATA is {len} bytes; the RDLENGTH limit is {}", u16::MAX)]
    TooLong { len: usize },
    #[error(transparent)]
    Name(#[from] EncodeNameError),
    #[error(transparent)]
    Value(#[from] ParseRecordValueError),
    #[error(transparent)]
    Mailbox(#[from] ParseMailboxError),
}

/// Wire-format RDATA bytes, capped at the RDLENGTH u16 limit
/// (RFC 1035, Section 3.2.1) by construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rdata(Vec<u8>);

impl Rdata {
    /// Render the presentation form of a derived row's RDATA of `record_type`,
    /// as `dig` prints it; the base64 row form when it does not parse.
    pub fn to_presentation(&self, record_type: DnssecRecordType) -> String {
        let mut parser = Parser::from_ref(self.as_bytes());

        AllRecordData::<_, ParsedName<_>>::parse_rdata(Rtype::from(record_type), &mut parser)
            .ok()
            .flatten()
            .filter(|_| parser.remaining() == 0)
            .map_or_else(|| self.to_base64(), |data| data.to_string())
    }

    /// Wrap wire-format record data after checking its length limit.
    pub fn new(bytes: Vec<u8>) -> Result<Self, EncodeRdataError> {
        if bytes.len() > usize::from(u16::MAX) {
            return Err(EncodeRdataError::TooLong { len: bytes.len() });
        }

        Ok(Self(bytes))
    }

    /// Return the wire-format record data bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the record data and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Render the base64 presentation fallback for rows whose RDATA does not parse.
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.0)
    }
}

/// The row form (`dnssec_records.rdata`, `zone_journal.record_rdata`) is the
/// wire bytes themselves, in a binary column.
impl<DB: sqlx::Database> sqlx::Type<DB> for Rdata
where
    Vec<u8>: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <Vec<u8> as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <Vec<u8> as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Rdata
where
    Vec<u8>: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        self.0.encode_by_ref(buffer)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Rdata
where
    Vec<u8>: sqlx::Decode<'r, DB>,
{
    /// Read the row form; bytes over the 16-bit RDATA limit fail the row.
    fn decode(value: <DB as sqlx::Database>::ValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<'r, DB>>::decode(value)?;
        Ok(Self::new(bytes)?)
    }
}

impl Rdata {
    /// Encode record or journal columns as wire RDATA.
    /// TXT remains opaque bytes for canonical record-set ordering.
    pub(crate) fn from_columns(
        record_type: RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> Result<Self, EncodeRdataError> {
        Ok(match record_type {
            RecordType::Wks => WksRecordValue::parse(value)?.to_rdata()?,
            RecordType::A => ARecordValue::parse(value)?.to_rdata()?,
            RecordType::Aaaa => AaaaRecordValue::parse(value)?.to_rdata()?,
            RecordType::Caa => CaaRecordValue::parse(value)?.to_rdata()?,
            RecordType::Cname | RecordType::Dname | RecordType::Ns | RecordType::Ptr => {
                Self::new(name::encode_name(value)?)?
            }
            RecordType::Ds => DsRecordValue::parse(value)?.to_rdata()?,
            RecordType::Mx => MxRecordValue::parse(value, priority)?.to_rdata()?,
            RecordType::Naptr => NaptrRecordValue::parse(value)?.to_rdata()?,
            RecordType::Txt => Self::new(TxtRecordValue::from_row(value)?.into_rdata())?,
            RecordType::Srv => SrvRecordValue::parse(value, priority)?.to_rdata()?,
            RecordType::Sshfp => SshfpRecordValue::parse(value)?.to_rdata()?,
            RecordType::Tlsa => TlsaRecordValue::parse(value)?.to_rdata()?,
        })
    }
}

#[cfg(test)]
mod tests;
