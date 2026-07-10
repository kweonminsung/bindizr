//! Per-record-type parsing, validation, and storage encoding of record values.

use std::borrow::Cow;

use crate::{error::ServiceError, model::record::RecordType};

mod a;
mod aaaa;
mod cname;
mod common;
mod mx;
mod ns;
mod ptr;
mod soa;
mod srv;
mod txt;

use a::ARecordValue;
use aaaa::AaaaRecordValue;
use cname::CnameRecordValue;
use mx::MxRecordValue;
use ns::NsRecordValue;
use ptr::PtrRecordValue;
use soa::SoaRecordValue;
use srv::SrvRecordValue;
use txt::TxtRecordValue;

pub(super) fn validate_record_value(
    record_type: &RecordType,
    value: &str,
    priority: Option<i32>,
) -> Result<(), ServiceError> {
    match record_type {
        RecordType::A => ARecordValue::parse(value).map(|_| ()),
        RecordType::AAAA => AaaaRecordValue::parse(value).map(|_| ()),
        RecordType::CNAME => CnameRecordValue::parse(value).map(|_| ()),
        RecordType::MX => MxRecordValue::parse(value, priority)?.validate(),
        RecordType::TXT => {
            let _ = TxtRecordValue::parse(value);
            Ok(())
        }
        RecordType::NS => NsRecordValue::parse(value).map(|_| ()),
        RecordType::SOA => SoaRecordValue::parse(value)?.validate(),
        RecordType::SRV => SrvRecordValue::parse(value, priority)?.validate(),
        RecordType::PTR => PtrRecordValue::parse(value).map(|_| ()),
    }
}

pub(super) fn record_values_equal(
    left: &str,
    left_priority: Option<i32>,
    right: &str,
    right_priority: Option<i32>,
    record_type: &RecordType,
) -> bool {
    canonical_record_value(left, left_priority, record_type)
        == canonical_record_value(right, right_priority, record_type)
}

pub(super) fn is_null_mx_record_value(value: &str, priority: Option<i32>) -> bool {
    MxRecordValue::parse(value, priority)
        .map(|parsed| parsed.priority == 0 && parsed.target.trim() == ".")
        .unwrap_or(false)
}

/// Canonical form used only to compare two values. Borrows the input where the
/// canonical form is the input (TXT, and every type whose parse fails), so the
/// comparison-heavy validation loops do not allocate.
fn canonical_record_value<'a>(
    value: &'a str,
    fallback_priority: Option<i32>,
    record_type: &RecordType,
) -> Cow<'a, str> {
    match record_type {
        RecordType::A => ARecordValue::parse(value)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or(Cow::Borrowed(value)),
        RecordType::AAAA => AaaaRecordValue::parse(value)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or(Cow::Borrowed(value)),
        RecordType::CNAME => CnameRecordValue::parse(value)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or_else(|_| Cow::Owned(common::canonical_domain_value(value))),
        RecordType::MX => MxRecordValue::parse(value, fallback_priority)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or(Cow::Borrowed(value)),
        RecordType::TXT => TxtRecordValue::parse(value).canonical(),
        RecordType::NS => NsRecordValue::parse(value)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or_else(|_| Cow::Owned(common::canonical_domain_value(value))),
        RecordType::SOA => SoaRecordValue::parse(value)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or(Cow::Borrowed(value)),
        RecordType::SRV => SrvRecordValue::parse(value, fallback_priority)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or(Cow::Borrowed(value)),
        RecordType::PTR => PtrRecordValue::parse(value)
            .map(|parsed| Cow::Owned(parsed.canonical()))
            .unwrap_or_else(|_| Cow::Owned(common::canonical_domain_value(value))),
    }
}
