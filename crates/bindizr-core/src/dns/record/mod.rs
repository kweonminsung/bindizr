//! Stored DNS record value types — per-type parsing, validation, and
//! canonicalization — plus their shared helpers and, in `rdata`, the one
//! stored-columns → wire-RDATA encoding. The `RecordType` methods in
//! `model::record` dispatch into these types.

mod a;
mod aaaa;
mod caa;
mod cname;
mod ds;
mod mx;
mod ns;
mod ptr;
mod rdata;
mod soa;
mod srv;
mod sshfp;
mod tlsa;
mod txt;
mod value;

pub(crate) use a::ARecordValue;
pub(crate) use aaaa::AaaaRecordValue;
pub(crate) use caa::CaaRecordValue;
pub(crate) use cname::CnameRecordValue;
pub(crate) use ds::DsRecordValue;
pub use mx::MxRecordValue;
pub(crate) use ns::NsRecordValue;
pub(crate) use ptr::PtrRecordValue;
pub use rdata::{EncodedRdata, Rdata};
pub use soa::{SoaMailbox, SoaRecordValue};
pub(crate) use srv::SrvRecordValue;
pub(crate) use sshfp::SshfpRecordValue;
pub(crate) use tlsa::TlsaRecordValue;
pub use txt::{TxtContent, TxtRecordValue};
