use std::fmt;
use std::str::FromStr;

use sqlx::FromRow;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use thiserror::Error;

use crate::dns::name::OwnerName;
use crate::dns::record::Rdata;
use crate::dns::{Serial, Ttl};
use crate::model::dnssec_record::{DnssecRecordType, ParseDnssecRecordTypeError};
use crate::model::record::RecordType;
use crate::model::zone::ZoneId;

/// One IXFR record change; a CHECK constraint requires exactly one of
/// `record_value` or `record_rdata`, according to `derived`.
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ZoneChange {
    pub zone_id: ZoneId,
    pub serial: Serial,
    #[sqlx(try_from = "String")]
    pub operation: ChangeOperation,
    pub record_name: OwnerName,
    #[sqlx(try_from = "String")]
    pub record_type: JournalRecordType,
    /// User rows and SOA markers: the record's row-form value.
    pub record_value: Option<String>,
    /// Derived rows: the exact wire RDATA the signer produced — signatures
    /// cover these bytes, so IXFR must emit them unre-encoded.
    pub record_rdata: Option<Rdata>,
    pub record_ttl: Ttl,
    pub record_priority: Option<i32>,
}

/// A journal operation column holding neither ADD nor DEL.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown journal operation '{value}'")]
pub struct ParseChangeOperationError {
    pub value: String,
}

/// What a journal row did to its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOperation {
    Add,
    Delete,
}

impl ChangeOperation {
    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "ADD",
            Self::Delete => "DEL",
        }
    }
}

impl FromStr for ChangeOperation {
    type Err = ParseChangeOperationError;

    /// Parse the stored text of a change operation.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ADD" => Ok(Self::Add),
            "DEL" => Ok(Self::Delete),
            other => Err(ParseChangeOperationError {
                value: other.to_string(),
            }),
        }
    }
}

impl TryFrom<String> for ChangeOperation {
    type Error = ParseChangeOperationError;

    /// Validate and convert the stored value into a change operation.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse::<Self>()
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for ChangeOperation
where
    String: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for ChangeOperation
where
    String: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        self.as_str().to_string().encode_by_ref(buffer)
    }
}

/// A journal row's record type: the column spans both the user plane
/// (`RecordType`) and the derived DNSSEC plane, stored as one mnemonic text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalRecordType {
    User(RecordType),
    Derived(DnssecRecordType),
    /// Apex SOA transition marker; the SOA itself lives in zone columns and
    /// `zone_versions`, never in a record row.
    Soa,
}

impl JournalRecordType {
    /// Return whether this is a signer-generated DNSSEC change, served by IXFR
    /// but skipped during rewind and diffs: rollback re-signs the restored
    /// user records.
    pub fn is_derived(self) -> bool {
        matches!(self, Self::Derived(_))
    }

    /// Return the canonical text representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User(record_type) => record_type.as_str(),
            Self::Derived(record_type) => record_type.as_str(),
            Self::Soa => "SOA",
        }
    }
}

impl fmt::Display for JournalRecordType {
    /// Write the journal record type in its display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for JournalRecordType {
    type Error = ParseDnssecRecordTypeError;

    /// Validate and convert the stored value into a journal record type.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.eq_ignore_ascii_case("SOA") {
            return Ok(Self::Soa);
        }
        if let Ok(record_type) = value.parse::<RecordType>() {
            return Ok(Self::User(record_type));
        }

        value.parse::<DnssecRecordType>().map(Self::Derived)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for JournalRecordType
where
    String: sqlx::Type<DB>,
{
    /// Return the SQL type used to store this value.
    fn type_info() -> DB::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    /// Return whether the SQL type can store this value.
    fn compatible(ty: &DB::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for JournalRecordType
where
    String: sqlx::Encode<'q, DB>,
{
    /// Encode this value using its database representation.
    fn encode_by_ref(
        &self,
        buffer: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<IsNull, BoxDynError> {
        self.as_str().to_string().encode_by_ref(buffer)
    }
}
