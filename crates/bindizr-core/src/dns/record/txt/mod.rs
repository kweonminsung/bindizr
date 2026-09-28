use super::{ParseRecordValueError, value::MAX_RECORD_RDATA};

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
    /// Parse a presentation-form value: a leading `"` reads space-separated
    /// quoted strings (max 255 bytes each, `\"`/`\\`/`\DDD` escapes per
    /// RFC 1035, Section 5.1); any other value is one raw string kept
    /// byte-for-byte, split at 255 bytes on UTF-8 boundaries.
    pub fn parse(value: &str) -> Result<Self, ParseRecordValueError> {
        if !value.trim().starts_with('"') {
            if value.is_empty() {
                return Err(ParseRecordValueError::Empty { field: "TXT value" });
            }
            return Ok(Self::from_string(value));
        }

        let segments = parse_quoted_segments(value.trim())?;
        Self::from_segments(segments.iter().map(String::as_str))
    }

    /// Wrap raw RDATA bytes, validating the character-string chain.
    pub(crate) fn from_rdata(rdata: &[u8]) -> Result<Self, ParseRecordValueError> {
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
        let mut rdata = Vec::new();
        let mut has_segments = false;
        for segment in segments {
            has_segments = true;
            let bytes = segment.as_bytes();
            if bytes.len() > 255 {
                return Err(ParseRecordValueError::CharStringTooLong {
                    field: "TXT character-string",
                });
            }
            rdata.push(bytes.len() as u8);
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

        for (idx, ch) in value.char_indices() {
            let char_len = ch.len_utf8();
            if chunk_len + char_len > 255 {
                rdata.push(chunk_len as u8);
                rdata.extend_from_slice(&value.as_bytes()[chunk_start..idx]);
                chunk_start = idx;
                chunk_len = 0;
            }
            chunk_len += char_len;
        }

        rdata.push(chunk_len as u8);
        rdata.extend_from_slice(&value.as_bytes()[chunk_start..]);
        Self(rdata)
    }

    /// Bounded so the record fits one transfer message; enforced here so a
    /// stored row cannot poison an AXFR.
    pub fn validate(&self) -> Result<(), ParseRecordValueError> {
        if self.0.len() > MAX_RECORD_RDATA {
            return Err(ParseRecordValueError::TxtTooLong {
                max: MAX_RECORD_RDATA,
                len: self.0.len(),
            });
        }
        Ok(())
    }

    /// Strict row-form parse: space-separated quoted character-strings only;
    /// `None` if the value is not in that form.
    pub fn from_presentation(stored: &str) -> Option<Self> {
        let segments = parse_quoted_segments(stored.trim()).ok()?;
        Self::from_segments(segments.iter().map(String::as_str)).ok()
    }

    /// Decode into character-strings, collapsing a single segment into
    /// [`TxtContent::Single`]; `None` on empty RDATA or non-UTF-8.
    pub fn to_content(&self) -> Option<TxtContent> {
        if self.0.is_empty() {
            return None;
        }

        let mut segments = Vec::new();
        for chunk in char_strings(&self.0)? {
            segments.push(std::str::from_utf8(chunk).ok()?.to_string());
        }

        match segments.as_slice() {
            [single] => Some(TxtContent::Single(single.clone())),
            _ => Some(TxtContent::Segments(segments)),
        }
    }

    /// The row form: each character-string quoted, space-separated, escaped
    /// per RFC 1035, Section 5.1; canonical, so rows compare as text.
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
    pub(crate) fn into_rdata(self) -> Vec<u8> {
        self.0
    }
}

/// Parse quoted TXT character strings and their escapes.
fn parse_quoted_segments(trimmed: &str) -> Result<Vec<String>, ParseRecordValueError> {
    let mut segments = Vec::new();
    let mut bytes = trimmed.bytes().peekable();

    while let Some(byte) = bytes.next() {
        if byte != b'"' {
            return Err(ParseRecordValueError::TxtUnseparated);
        }

        // Decode escapes before checking the character-string's wire byte length.
        let mut segment: Vec<u8> = Vec::new();
        loop {
            match bytes.next() {
                Some(b'"') => break,
                Some(b'\\') => match bytes.next() {
                    Some(d @ b'0'..=b'9') => {
                        let d2 = bytes.next().filter(u8::is_ascii_digit);
                        let d3 = bytes.next().filter(u8::is_ascii_digit);
                        let (Some(d2), Some(d3)) = (d2, d3) else {
                            return Err(ParseRecordValueError::InvalidEscape {
                                field: "TXT value",
                            });
                        };
                        let code =
                            (d - b'0') as u16 * 100 + (d2 - b'0') as u16 * 10 + (d3 - b'0') as u16;
                        if code > 255 {
                            return Err(ParseRecordValueError::InvalidEscape {
                                field: "TXT value",
                            });
                        }
                        segment.push(code as u8);
                    }
                    Some(escaped) => segment.push(escaped),
                    None => return Err(ParseRecordValueError::TxtDanglingEscape),
                },
                Some(other) => segment.push(other),
                None => return Err(ParseRecordValueError::TxtUnterminatedQuote),
            }
        }

        if segment.len() > 255 {
            return Err(ParseRecordValueError::CharStringTooLong {
                field: "TXT character-string",
            });
        }
        segments.push(
            String::from_utf8(segment)
                .map_err(|_| ParseRecordValueError::NotUtf8 { field: "TXT value" })?,
        );

        // Require spaces between quoted strings while preserving each wire segment.
        match bytes.next() {
            None => break,
            Some(b' ') => {
                while bytes.peek() == Some(&b' ') {
                    bytes.next();
                }
                if bytes.peek().is_none() {
                    break;
                }
            }
            Some(_) => {
                return Err(ParseRecordValueError::TxtUnseparated);
            }
        }
    }

    if segments.is_empty() {
        return Err(ParseRecordValueError::TxtNoCharString);
    }
    Ok(segments)
}

/// Split RDATA into its length-prefixed character-strings, or `None` when a
/// length octet overruns the buffer. The one place the prefix is interpreted;
/// the accessors above slice only what this returns.
fn char_strings(rdata: &[u8]) -> Option<Vec<&[u8]>> {
    let mut segments = Vec::new();
    let mut pos = 0usize;
    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        pos += 1;
        segments.push(rdata.get(pos..pos + len)?);
        pos += len;
    }
    Some(segments)
}

/// Render bytes as a quoted TXT character-string, escaping `"`/`\` and any
/// non-printable byte as a `\DDD` decimal escape (RFC 1035, Section 5.1).
pub fn to_quoted_charstr(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(byte as char),
            _ => out.push_str(&format!("\\{:03}", byte)),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;
