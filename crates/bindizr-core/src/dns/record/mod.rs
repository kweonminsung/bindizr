//! Parse and canonicalize stored record values and encode their wire RDATA.
//! `model::record::RecordType` dispatches to the per-type implementations.

mod a;
mod aaaa;
mod caa;
mod cname;
mod dname;
mod ds;
mod error;
mod mx;
mod naptr;
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
pub use dname::DnameRecordValue;
pub use ds::DsRecordValue;
pub use error::ParseRecordValueError;
pub use mx::MxRecordValue;
pub use naptr::{NaptrRecordValue, NaptrRegexpError};
pub use ns::NsRecordValue;
pub use ptr::PtrRecordValue;
pub(crate) use rdata::EncodedRdata;
pub use rdata::{EncodeRdataError, Rdata};
pub use soa::{ParseMailboxError, SoaMailbox, SoaRecordValue};
pub use srv::SrvRecordValue;
pub use sshfp::SshfpRecordValue;
pub use tlsa::TlsaRecordValue;
pub use txt::{TxtContent, TxtRecordValue, to_quoted_charstr};
pub(crate) use value::DEFAULT_PRIORITY;
