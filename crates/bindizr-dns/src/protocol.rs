//! Shared DNS wire-protocol constants. Record TYPE codes live on
//! `RecordType::wire_code` instead.

/// Fixed length of a DNS message header, in bytes.
pub(crate) const DNS_HEADER_LEN: usize = 12;
/// Maximum size of a DNS message carried over TCP (16-bit length prefix).
pub(crate) const DNS_TCP_MAX_SIZE: usize = 65535;

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
