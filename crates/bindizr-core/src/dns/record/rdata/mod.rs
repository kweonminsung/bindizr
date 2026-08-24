//! Stored record columns → wire-format RDATA. [`EncodedRdata::from_columns`]
//! is the one stored-columns → wire-RDATA mapping: the XFR encoder and the
//! DNSSEC signer both consume it, so the bytes a signature covers are
//! byte-identical to the bytes a transfer serves.

use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine;

use super::{DsRecordValue, MxRecordValue, SrvRecordValue, TxtRecordValue};
use crate::{dns::name::encode_name, model::record::RecordType};

const JOURNAL_VALUE_PREFIX: &str = "bindizr:rdata:v1:";

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

    /// The row form (`dnssec_records.rdata`): plain base64.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.0)
    }

    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("RDATA is not base64: {}", e))?;
        Self::new(bytes)
    }

    /// The journal form (`zone_journal.record_value`): prefixed base64, so a
    /// derived row's wire bytes can share the column with plain user values.
    pub fn to_journal_value(&self) -> String {
        format!("{}{}", JOURNAL_VALUE_PREFIX, self.to_base64())
    }

    /// Decode the journal form; `None` if it is not valid.
    pub fn from_journal_value(stored: &str) -> Option<Self> {
        let encoded = stored.strip_prefix(JOURNAL_VALUE_PREFIX)?;
        Self::from_base64(encoded).ok()
    }
}

/// Decodes the row form, so a row column can hold RDATA directly.
impl TryFrom<String> for Rdata {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_base64(&value)
    }
}

/// The write half: binding renders [`Rdata::to_base64`], the row form
/// [`TryFrom<String>`] decodes.
impl<DB: sqlx::Database> sqlx::Type<DB> for Rdata
where
    String: sqlx::Type<DB>,
{
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for Rdata
where
    String: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.to_base64().encode_by_ref(buf)
    }
}

/// A stored record's wire RR type number and RDATA bytes.
pub struct EncodedRdata {
    pub record_type: u16,
    pub rdata: Rdata,
}

impl EncodedRdata {
    /// Wire RDATA for stored record columns (records and journal rows share
    /// this shape). `Ok(None)` means the type has no wire mapping here — the
    /// `SOA` journal markers; the caller decides whether that is a skip or an
    /// error.
    ///
    /// TXT is one opaque byte mapping for both stored forms: canonical RRset
    /// order is a byte comparison, and mixing differently derived TXT values in
    /// one RRset would not sort as one.
    pub fn from_columns(
        record_type: &RecordType,
        value: &str,
        priority: Option<i32>,
    ) -> Result<Option<EncodedRdata>, String> {
        let rdata = match record_type {
            RecordType::A => {
                let addr: Ipv4Addr = value
                    .parse()
                    .map_err(|_| format!("Invalid A record: {}", value))?;
                addr.octets().to_vec()
            }
            RecordType::AAAA => {
                let addr: Ipv6Addr = value
                    .parse()
                    .map_err(|_| format!("Invalid AAAA record: {}", value))?;
                addr.octets().to_vec()
            }
            RecordType::CNAME | RecordType::NS | RecordType::PTR => encode_name(value)?,
            RecordType::DS => {
                let (key_tag, algorithm, digest_type, digest) =
                    DsRecordValue::parse(value)?.wire_fields();
                let mut rdata = Vec::with_capacity(4 + digest.len());
                rdata.extend_from_slice(&key_tag.to_be_bytes());
                rdata.push(algorithm);
                rdata.push(digest_type);
                rdata.extend_from_slice(&digest);
                rdata
            }
            RecordType::MX => {
                let (preference, target) = MxRecordValue::wire_fields(value, priority)?;
                let mut rdata = preference.to_be_bytes().to_vec();
                rdata.extend_from_slice(&encode_name(target)?);
                rdata
            }
            RecordType::SRV => {
                let (srv_priority, weight, port, target) =
                    SrvRecordValue::wire_fields(value, priority)?;
                let mut rdata = Vec::with_capacity(6 + target.len() + 2);
                rdata.extend_from_slice(&srv_priority.to_be_bytes());
                rdata.extend_from_slice(&weight.to_be_bytes());
                rdata.extend_from_slice(&port.to_be_bytes());
                rdata.extend_from_slice(&encode_name(target)?);
                rdata
            }
            RecordType::TXT => match TxtRecordValue::from_encoded(value) {
                // Operator-supplied raw rdata is passed through unchanged.
                Some(raw) => raw.into_rdata(),
                None => TxtRecordValue::from_string(value).into_rdata(),
            },
            RecordType::SOA => return Ok(None),
        };

        Ok(Some(Self {
            record_type: record_type.wire_type(),
            rdata: Rdata::new(rdata)?,
        }))
    }
}

#[cfg(test)]
mod tests;
