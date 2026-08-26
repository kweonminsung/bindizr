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

pub use a::ARecordValue;
pub use aaaa::AaaaRecordValue;
pub use caa::CaaRecordValue;
pub use cname::CnameRecordValue;
pub use ds::DsRecordValue;
pub use mx::MxRecordValue;
pub use ns::NsRecordValue;
pub use ptr::PtrRecordValue;
pub use rdata::{EncodedRdata, Rdata};
pub use soa::{SoaMailbox, SoaRecordValue};
pub use srv::SrvRecordValue;
pub use sshfp::SshfpRecordValue;
pub use tlsa::TlsaRecordValue;
pub use txt::{TxtContent, TxtRecordValue};
