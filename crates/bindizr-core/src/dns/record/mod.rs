//! Stored DNS record value types — per-type parsing, validation, and
//! canonicalization — plus their shared helpers and, in `rdata`, the one
//! stored-columns → wire-RDATA encoding. The `RecordType` methods in
//! `model::record` dispatch into these types.

mod a;
mod aaaa;
mod cname;
mod ds;
mod mx;
mod ns;
mod ptr;
mod rdata;
mod soa;
mod srv;
mod txt;
mod value;

pub(crate) use a::ARecordValue;
pub(crate) use aaaa::AaaaRecordValue;
pub(crate) use cname::CnameRecordValue;
pub(crate) use ds::DsRecordValue;
pub use mx::MxRecordValue;
pub(crate) use ns::NsRecordValue;
pub(crate) use ptr::PtrRecordValue;
pub use rdata::{EncodedRdata, Rdata};
pub use soa::{SoaMailbox, SoaRecordValue};
pub(crate) use srv::SrvRecordValue;
pub use txt::{TxtContent, TxtRecordValue};
