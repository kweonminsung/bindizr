use std::str;

use crate::dns::record::value::{MAX_CHARACTER_STRING_LEN, MAX_RECORD_RDATA};
use crate::dns::record::{ParseRecordValueError, value};

/// The content of a TXT value: a single string or multiple character-strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxtContent {
    Single(String),
    Segments(Vec<String>),
}

/// A TXT value as raw RDATA (length-prefixed character-strings); the row form
/// is its canonical presentation rendering ([`Self::to_presentation`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecordValue(Vec<u8>);

impl TxtRecordValue {
    /// Parse quoted strings and escapes per RFC 1035, Section 5.1, or unquoted raw text.
    /// Raw text splits at UTF-8 boundaries; each segment is at most 255 bytes.
    pub fn parse(value: &str) -> Result<Self, ParseRecordValueError> {
        if !value.trim().starts_with('"') {
            if value.is_empty() {
                return Err(ParseRecordValueError::Empty { field: "TXT value" });
            }
            return Ok(Self::from_string(value));
        }

        Self::from_presentation(value)
    }

    /// Wrap raw RDATA bytes, validating the character-string chain.
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, ParseRecordValueError> {
        if rdata.is_empty() || char_strings(rdata).is_none() {
            return Err(ParseRecordValueError::TxtRdata);
        }

        Ok(Self(rdata.to_vec()))
    }

    /// Encode character-strings; errors if a segment exceeds 255 bytes or no
    /// segments are given.
    pub fn from_segments<'a, I>(segments: I) -> Result<Self, ParseRecordValueError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        Self::from_octet_segments(segments.into_iter().map(str::as_bytes))
    }

    /// Encode arbitrary character-string octets without imposing an application charset.
    pub fn from_octet_segments<'a>(
        segments: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, ParseRecordValueError> {
        let mut rdata = Vec::new();
        let mut has_segments = false;

        for bytes in segments {
            has_segments = true;

            let len = u8::try_from(bytes.len()).map_err(|_| {
                ParseRecordValueError::CharStringTooLong {
                    field: "TXT character-string",
                }
            })?;
            rdata.push(len);
            rdata.extend_from_slice(bytes);
        }

        if !has_segments {
            return Err(ParseRecordValueError::TxtNoCharString);
        }

        Ok(Self(rdata))
    }

    /// Encode a single string, splitting it into 255-byte character-strings on
    /// UTF-8 boundaries.
    pub fn from_string(value: &str) -> Self {
        let mut rdata = Vec::new();
        let mut chunk_start = 0usize;
        let mut chunk_len = 0usize;

        for (index, ch) in value.char_indices() {
            let char_len = ch.len_utf8();

            if chunk_len + char_len > MAX_CHARACTER_STRING_LEN {
                rdata.push(chunk_len as u8);
                rdata.extend_from_slice(&value.as_bytes()[chunk_start..index]);
                chunk_start = index;
                chunk_len = 0;
            }

            chunk_len += char_len;
        }

        rdata.push(chunk_len as u8);
        rdata.extend_from_slice(&value.as_bytes()[chunk_start..]);

        Self(rdata)
    }

    /// Validate the length bound that lets the record fit one transfer message;
    /// enforced here so a stored row cannot poison an AXFR.
    pub fn validate(&self) -> Result<(), ParseRecordValueError> {
        if self.0.len() > MAX_RECORD_RDATA {
            return Err(ParseRecordValueError::TxtTooLong {
                max: MAX_RECORD_RDATA,
                len: self.0.len(),
            });
        }

        Ok(())
    }

    /// Parse the row form strictly: space-separated quoted character-strings
    /// only, refusing anything else with the reason it is not that form.
    pub fn from_presentation(value: &str) -> Result<Self, ParseRecordValueError> {
        let segments = parse_quoted_segments(value.trim())?;
        Self::from_octet_segments(segments.iter().map(Vec::as_slice))
    }

    /// Decode into character-strings, collapsing a single segment into
    /// [`TxtContent::Single`]; `None` on empty RDATA or non-UTF-8.
    pub fn to_content(&self) -> Option<TxtContent> {
        if self.0.is_empty() {
            return None;
        }

        let mut segments = Vec::new();

        for chunk in char_strings(&self.0)? {
            segments.push(str::from_utf8(chunk).ok()?.to_string());
        }

        match segments.as_slice() {
            [single] => Some(TxtContent::Single(single.clone())),
            _ => Some(TxtContent::Segments(segments)),
        }
    }

    /// Render the row form: each character-string quoted, space-separated,
    /// escaped per RFC 1035, Section 5.1; canonical, so rows compare as text.
    pub fn to_presentation(&self) -> String {
        // Every constructor validated the chain, so the walk cannot fail.
        let chunks = char_strings(&self.0).expect("TXT RDATA validated at construction");
        chunks
            .iter()
            .map(|chunk| to_quoted_charstr(chunk))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Consume the TXT segments and encode their length-prefixed wire data.
    pub fn into_rdata(self) -> Vec<u8> {
        self.0
    }
}

/// Parse quoted TXT character strings, each decoded by the shared escape
/// decoder, separated by one or more spaces.
fn parse_quoted_segments(trimmed: &str) -> Result<Vec<Vec<u8>>, ParseRecordValueError> {
    let mut segments = Vec::new();
    let mut rest = trimmed;

    while !rest.is_empty() {
        if !rest.starts_with('"') {
            return Err(ParseRecordValueError::TxtUnseparated);
        }

        // Decode escapes before checking the character-string's wire byte length.
        let (segment, after) = value::parse_string_octets("TXT value", rest)?;

        if segment.len() > MAX_CHARACTER_STRING_LEN {
            return Err(ParseRecordValueError::CharStringTooLong {
                field: "TXT character-string",
            });
        }

        segments.push(segment);

        // Require spaces between quoted strings while preserving each wire segment.
        rest = match after.strip_prefix(' ') {
            Some(spaced) => spaced.trim_start_matches(' '),
            None if after.is_empty() => after,
            None => return Err(ParseRecordValueError::TxtUnseparated),
        };
    }

    if segments.is_empty() {
        return Err(ParseRecordValueError::TxtNoCharString);
    }

    Ok(segments)
}

/// Split length-prefixed character-strings, returning `None` on buffer overrun.
fn char_strings(rdata: &[u8]) -> Option<Vec<&[u8]>> {
    let mut segments = Vec::new();
    let mut pos = 0usize;

    while pos < rdata.len() {
        let len = usize::from(rdata[pos]);
        pos += 1;
        segments.push(rdata.get(pos..pos + len)?);
        pos += len;
    }

    Some(segments)
}

/// Render bytes as a quoted TXT character-string, escaping `"`/`\` and any
/// non-printable byte as a `\DDD` decimal escape (RFC 1035, Section 5.1).
pub fn to_quoted_charstr(bytes: &[u8]) -> String {
    let mut text = "\"".to_string();

    for &byte in bytes {
        match byte {
            b'"' => text.push_str("\\\""),
            b'\\' => text.push_str("\\\\"),
            0x20..=0x7e => text.push(char::from(byte)),
            _ => text.push_str(&format!("\\{byte:03}")),
        }
    }

    text.push('"');

    text
}

#[cfg(test)]
mod tests;
