//! Stored DNS record value types — per-type parsing, validation, and
//! canonicalization — plus their shared helpers. The `RecordType` methods in
//! `model::record` dispatch into these types.

mod a;
mod aaaa;
mod cname;
mod mx;
mod ns;
mod ptr;
mod soa;
mod srv;
mod txt;
mod value;

pub(crate) use a::ARecordValue;
pub(crate) use aaaa::AaaaRecordValue;
pub(crate) use cname::CnameRecordValue;
pub use mx::MxRecordValue;
pub(crate) use ns::NsRecordValue;
pub(crate) use ptr::PtrRecordValue;
pub use soa::SoaMailbox;
pub(crate) use soa::SoaRecordValue;
pub(crate) use srv::SrvRecordValue;
pub(crate) use txt::TxtRecordValue;
pub use txt::{TxtContent, TxtRdata};
pub use value::display_record_owner_name;
