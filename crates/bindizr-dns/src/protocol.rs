//! Shared DNS wire-protocol constants. Record TYPE codes live on
//! `RecordType::wire_code` instead.

/// Fixed length of a DNS message header, in bytes.
pub(crate) const DNS_HEADER_LEN: usize = 12;
/// Maximum size of a DNS message carried over TCP (16-bit length prefix).
pub(crate) const DNS_TCP_MAX_SIZE: usize = 65535;
/// Top two bits set marks a compression pointer in a name (RFC 1035 §4.1.4).
pub(crate) const DNS_COMPRESSION_POINTER_MASK: u8 = 0xC0;

/// OPCODE for UPDATE messages (RFC 2136).
pub(crate) const DNS_OPCODE_UPDATE: u8 = 5;

// DNS CLASS values (RFC 1035 / 2136).
pub(crate) const CLASS_IN: u16 = 1;
pub(crate) const CLASS_NONE: u16 = 254;
pub(crate) const CLASS_ANY: u16 = 255;

/// Meta TYPE matching any record (QTYPE/UPDATE "ANY").
pub(crate) const TYPE_ANY: u16 = 255;
/// TSIG meta record TYPE (RFC 8945).
pub(crate) const TYPE_TSIG: u16 = 250;

// Response codes (RFC 1035 / 2136).
pub(crate) const RCODE_NOERROR: u8 = 0;
pub(crate) const RCODE_FORMERR: u8 = 1;
pub(crate) const RCODE_SERVFAIL: u8 = 2;
pub(crate) const RCODE_NXDOMAIN: u8 = 3;
pub(crate) const RCODE_REFUSED: u8 = 5;
pub(crate) const RCODE_YXDOMAIN: u8 = 6;
pub(crate) const RCODE_YXRRSET: u8 = 7;
pub(crate) const RCODE_NXRRSET: u8 = 8;
pub(crate) const RCODE_NOTAUTH: u8 = 9;
pub(crate) const RCODE_NOTZONE: u8 = 10;

// TSIG error codes (RFC 8945).
pub(crate) const TSIG_ERROR_BADSIG: u16 = 16;
pub(crate) const TSIG_ERROR_BADKEY: u16 = 17;
pub(crate) const TSIG_ERROR_BADTIME: u16 = 18;
