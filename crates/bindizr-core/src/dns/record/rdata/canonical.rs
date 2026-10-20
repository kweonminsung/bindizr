//! Canonical wire RDATA for comparison and DNSSEC signing.

use domain::{
    base::{
        Rtype,
        name::ParsedName,
        rdata::{ComposeRecordData, ParseAnyRecordData},
        wire::ParseError,
    },
    dep::octseq::parse::{Parser, ShortInput},
    rdata::AllRecordData,
};
use thiserror::Error;

use super::{EncodeRdataError, Rdata};

/// RDATA that cannot be parsed or canonicalized.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseRdataError {
    #[error("RDATA extends beyond the message: {0}")]
    Length(#[from] ShortInput),
    #[error("invalid RDATA: {0}")]
    Invalid(#[from] ParseError),
    #[error("RDATA has trailing bytes")]
    TrailingBytes,
    #[error(transparent)]
    Encoding(#[from] EncodeRdataError),
}

impl Rdata {
    /// Parse `len` RDATA bytes at `start`, resolving compressed names in `message`.
    /// Canonicalize names but preserve opaque bytes (RFC 2136, Section 1.1; RFC 3597, Sections 6–7).
    pub fn parse_canonical(
        record_type: Rtype,
        message: &[u8],
        start: usize,
        len: usize,
    ) -> Result<Self, ParseRdataError> {
        let mut parser = Parser::from_ref(message);
        parser.advance(start)?;
        let mut rdata = parser.parse_parser(len)?;
        let data = AllRecordData::<_, ParsedName<_>>::parse_any_rdata(record_type, &mut rdata)?;
        if rdata.remaining() != 0 {
            return Err(ParseRdataError::TrailingBytes);
        }
        let mut bytes = Vec::new();
        let Ok(()) = data.compose_canonical_rdata(&mut bytes);
        Ok(Self::new(bytes)?)
    }

    /// Canonicalize uncompressed RDATA for comparison or DNSSEC signing.
    pub fn to_canonical(&self, record_type: Rtype) -> Result<Self, ParseRdataError> {
        Self::parse_canonical(record_type, self.as_bytes(), 0, self.as_bytes().len())
    }
}
