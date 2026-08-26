//! Stored record columns → wire-format RDATA. [`EncodedRdata::from_columns`]
//! is the one stored-columns → wire-RDATA mapping: the XFR encoder and the
//! DNSSEC signer both consume it, so the bytes a signature covers are
//! byte-identical to the bytes a transfer serves.

use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine;

use super::{
    CaaRecordValue, DsRecordValue, MxRecordValue, SrvRecordValue, SshfpRecordValue,
    TlsaRecordValue, TxtRecordValue,
};
use crate::{dns::name::encode_name, model::record::RecordType};

/// Wire-format RDATA bytes, capped at the RDLENGTH u16 limit
/// (RFC 1035, Section 3.2.1) by construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rdata(Vec<u8>);

impl Rdata {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() > u16::MAX as usize {
            return Err(format!(
                "RDATA is {} bytes; the RDLENGTH limit is {}",
                bytes.len(),
                u16::MAX
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Base64 presentation fallback for rows whose RDATA does not parse.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.0)
    }
}

/// The row form (`dnssec_records.rdata`, `zone_journal.record_rdata`) is the
/// wire bytes themselves, in a binary column.
impl<DB: sqlx::Database> sqlx::Type<DB> for Rdata
where
    Vec<u8>: sqlx::Type<DB>,
{
    fn type_info() -> DB::TypeInfo {
        <Vec<u8> as sqlx::Type<DB>>::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        <Vec<u8> as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Rdata
where
    Vec<u8>: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.0.encode_by_ref(buf)
    }
}

impl<'r, DB: sqlx::Database> sqlx::Decode<'r, DB> for Rdata
where
    Vec<u8>: sqlx::Decode<'r, DB>,
{
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let bytes = <Vec<u8> as sqlx::Decode<'r, DB>>::decode(value)?;
        Self::new(bytes).map_err(Into::into)
    }
}

/// A stored record's wire RR type number and RDATA bytes.
pub struct EncodedRdata {
    pub record_type: u16,
    pub rdata: Rdata,
}

impl EncodedRdata {
    /// Wire RDATA for stored record columns (records and journal rows share
    /// this shape). TXT stays one opaque byte mapping: canonical RRset order
    /// is a byte comparison over the rdata.
    pub fn from_columns(
        record_type: &RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> Result<EncodedRdata, String> {
        let rdata = match record_type {
            RecordType::A => {
                let addr: Ipv4Addr = value
                    .parse()
                    .map_err(|_| format!("Invalid A record: {}", value))?;
                Rdata::new(addr.octets().to_vec())?
            }
            RecordType::AAAA => {
                let addr: Ipv6Addr = value
                    .parse()
                    .map_err(|_| format!("Invalid AAAA record: {}", value))?;
                Rdata::new(addr.octets().to_vec())?
            }
            RecordType::CAA => CaaRecordValue::parse(value)?.to_rdata()?,
            RecordType::CNAME | RecordType::NS | RecordType::PTR => {
                Rdata::new(encode_name(value)?)?
            }
            RecordType::DS => DsRecordValue::parse(value)?.to_rdata()?,
            RecordType::MX => MxRecordValue::parse(value, priority)?.to_rdata()?,
            // Stored TXT is always the presentation form; every entry path
            // writes it, so anything else here is corruption, not a plain string.
            RecordType::TXT => Rdata::new(
                TxtRecordValue::from_presentation(value)
                    .ok_or_else(|| {
                        format!("stored TXT value is not in presentation form: {value}")
                    })?
                    .into_rdata(),
            )?,
            RecordType::SRV => SrvRecordValue::parse(value, priority)?.to_rdata()?,
            RecordType::SSHFP => SshfpRecordValue::parse(value)?.to_rdata()?,
            RecordType::TLSA => TlsaRecordValue::parse(value)?.to_rdata()?,
        };

        Ok(Self {
            record_type: record_type.wire_type(),
            rdata,
        })
    }
}

#[cfg(test)]
mod tests;
