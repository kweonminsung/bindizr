use sqlx::FromRow;

use crate::{
    dns::name::OwnerName,
    model::{dnssec_record::DnssecRecordType, record::RecordType},
};

/// A single record add/delete change within a zone, used for IXFR.
#[derive(Debug, Clone, FromRow)]
pub struct ZoneChange {
    pub zone_id: i32,
    pub serial: i32,
    #[sqlx(try_from = "String")]
    pub operation: ChangeOperation,
    #[sqlx(try_from = "String")]
    pub record_name: OwnerName,
    #[sqlx(try_from = "String")]
    pub record_type: JournalRecordType,
    pub record_value: String,
    pub record_ttl: i32,
    pub record_priority: Option<i32>,
    /// Signer-generated DNSSEC change (RRSIG/NSEC/DNSKEY, wire-rdata encoded
    /// value). IXFR emits these like any change; history reconstruction and
    /// diffs skip them — the derived plane is re-signed, never restored.
    pub derived: bool,
}

/// What a journal row did to its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOperation {
    Add,
    Del,
}

impl ChangeOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeOperation::Add => "ADD",
            ChangeOperation::Del => "DEL",
        }
    }
}

impl TryFrom<String> for ChangeOperation {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ADD" => Ok(ChangeOperation::Add),
            "DEL" => Ok(ChangeOperation::Del),
            other => Err(format!("unknown journal operation '{}'", other)),
        }
    }
}

/// A journal row's record type: the column spans both the user plane
/// (`RecordType`) and the derived DNSSEC plane, stored as one mnemonic text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecordType {
    User(RecordType),
    Derived(DnssecRecordType),
}

impl JournalRecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            JournalRecordType::User(record_type) => record_type.as_str(),
            JournalRecordType::Derived(record_type) => record_type.as_str(),
        }
    }
}

impl std::fmt::Display for JournalRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for JournalRecordType {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(record_type) = value.parse::<RecordType>() {
            return Ok(JournalRecordType::User(record_type));
        }
        value
            .parse::<DnssecRecordType>()
            .map(JournalRecordType::Derived)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for ChangeOperation
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

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for ChangeOperation
where
    String: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.as_str().to_string().encode_by_ref(buf)
    }
}

impl<DB: sqlx::Database> sqlx::Type<DB> for JournalRecordType
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

impl<'q, DB: sqlx::Database> sqlx::Encode<'q, DB> for JournalRecordType
where
    String: sqlx::Encode<'q, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        self.as_str().to_string().encode_by_ref(buf)
    }
}
