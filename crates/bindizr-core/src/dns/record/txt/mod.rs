use base64::Engine;

const RAW_TXT_RDATA_PREFIX: &str = "bindizr:txt-rdata:v1:";

/// The content of a TXT value: a single string or multiple character-strings.
#[derive(Debug, PartialEq, Eq)]
pub enum TxtContent {
    Single(String),
    Segments(Vec<String>),
}

/// A TXT value as raw RDATA (length-prefixed character-strings); stored as a
/// prefixed base64 string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRdata(Vec<u8>);

impl TxtRdata {
    /// Wrap raw RDATA bytes as-is.
    pub fn from_rdata(rdata: &[u8]) -> Self {
        Self(rdata.to_vec())
    }

    /// Encode character-strings; errors if a segment exceeds 255 bytes or no
    /// segments are given.
    pub fn from_segments<'a, I>(segments: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut rdata = Vec::new();
        let mut has_segments = false;
        for segment in segments {
            has_segments = true;
            let bytes = segment.as_bytes();
            if bytes.len() > 255 {
                return Err("TXT character-string must be 255 bytes or less".to_string());
            }
            rdata.push(bytes.len() as u8);
            rdata.extend_from_slice(bytes);
        }
        if !has_segments {
            return Err("TXT record must contain at least one character-string".to_string());
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

    /// Parse a presentation-form value: a leading `"` reads space-separated
    /// quoted strings (max 255 bytes each, `\"`/`\\`/`\DDD` escapes per
    /// RFC 1035, Section 5.1); any other value is one raw string kept
    /// byte-for-byte, split at 255 bytes on UTF-8 boundaries.
    pub fn from_presentation(value: &str) -> Result<Self, String> {
        if !value.trim().starts_with('"') {
            if value.is_empty() {
                return Err("TXT value must not be empty".to_string());
            }
            return Ok(Self::from_string(value));
        }

        let segments = parse_quoted_segments(value.trim())?;
        Self::from_segments(segments.iter().map(String::as_str))
    }

    /// Decode a prefixed-base64 encoded value; `None` if it is not valid.
    pub fn from_encoded(stored: &str) -> Option<Self> {
        let encoded = stored.strip_prefix(RAW_TXT_RDATA_PREFIX)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()
            .filter(|rdata| is_valid_txt_rdata(rdata))
            .map(Self)
    }

    /// Decode into character-strings, collapsing a single segment into
    /// [`TxtContent::Single`]; `None` on empty RDATA or non-UTF-8.
    pub fn to_content(&self) -> Option<TxtContent> {
        if self.0.is_empty() {
            return None;
        }

        let mut pos = 0usize;
        let mut segments = Vec::new();

        while pos < self.0.len() {
            let chunk_len = self.0[pos] as usize;
            pos += 1;
            let chunk = std::str::from_utf8(&self.0[pos..pos + chunk_len]).ok()?;
            segments.push(chunk.to_string());
            pos += chunk_len;
        }

        match segments.as_slice() {
            [single] => Some(TxtContent::Single(single.clone())),
            _ => Some(TxtContent::Segments(segments)),
        }
    }

    /// Render as the canonical space-separated quoted form
    /// [`crate::model::record::RecordType::presentation_rdata`] produces, so round trips
    /// compare byte-equal.
    pub fn to_presentation(&self) -> String {
        let mut segments = Vec::new();
        let mut pos = 0usize;
        while pos < self.0.len() {
            let len = self.0[pos] as usize;
            pos += 1;
            segments.push(Self::quote_charstr(&self.0[pos..pos + len]));
            pos += len;
        }
        if segments.is_empty() {
            segments.push("\"\"".to_string());
        }
        segments.join(" ")
    }

    /// Render bytes as a quoted TXT character-string, escaping `"`/`\` and any
    /// non-printable byte as a `\DDD` decimal escape (RFC 1035, Section 5.1).
    pub fn quote_charstr(bytes: &[u8]) -> String {
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

    /// The encoded form: prefixed base64 of the raw RDATA.
    pub fn into_encoded(self) -> String {
        format!(
            "{}{}",
            RAW_TXT_RDATA_PREFIX,
            base64::engine::general_purpose::STANDARD.encode(&self.0)
        )
    }

    /// The raw RDATA bytes.
    pub fn into_rdata(self) -> Vec<u8> {
        self.0
    }
}

fn parse_quoted_segments(trimmed: &str) -> Result<Vec<String>, String> {
    let mut segments = Vec::new();
    let mut bytes = trimmed.bytes().peekable();

    while let Some(byte) = bytes.next() {
        if byte != b'"' {
            return Err("TXT character-strings must be separated by spaces".to_string());
        }

        let mut segment: Vec<u8> = Vec::new();
        loop {
            match bytes.next() {
                Some(b'"') => break,
                Some(b'\\') => match bytes.next() {
                    Some(d @ b'0'..=b'9') => {
                        let d2 = bytes.next().filter(u8::is_ascii_digit);
                        let d3 = bytes.next().filter(u8::is_ascii_digit);
                        let (Some(d2), Some(d3)) = (d2, d3) else {
                            return Err("TXT value contains an invalid \\DDD escape".to_string());
                        };
                        let code =
                            (d - b'0') as u16 * 100 + (d2 - b'0') as u16 * 10 + (d3 - b'0') as u16;
                        if code > 255 {
                            return Err("TXT value contains an invalid \\DDD escape".to_string());
                        }
                        segment.push(code as u8);
                    }
                    Some(escaped) => segment.push(escaped),
                    None => return Err("TXT value contains a dangling escape".to_string()),
                },
                Some(other) => segment.push(other),
                None => return Err("TXT value contains an unterminated quote".to_string()),
            }
        }

        if segment.len() > 255 {
            return Err("TXT character-string must be 255 bytes or less".to_string());
        }
        segments.push(
            String::from_utf8(segment).map_err(|_| "TXT value must be valid UTF-8".to_string())?,
        );

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
                return Err("TXT character-strings must be separated by spaces".to_string());
            }
        }
    }

    if segments.is_empty() {
        return Err("TXT record must contain at least one character-string".to_string());
    }
    Ok(segments)
}

fn is_valid_txt_rdata(rdata: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < rdata.len() {
        let chunk_len = rdata[pos] as usize;
        pos += 1;
        if pos + chunk_len > rdata.len() {
            return false;
        }
        pos += chunk_len;
    }
    true
}

pub(crate) struct TxtRecordValue<'a> {
    value: &'a str,
}

impl<'a> TxtRecordValue<'a> {
    pub(crate) fn parse(value: &'a str) -> Self {
        Self { value }
    }

    /// TXT values are stored already canonical.
    pub(crate) fn canonical(&self) -> std::borrow::Cow<'a, str> {
        std::borrow::Cow::Borrowed(self.value)
    }
}

#[cfg(test)]
mod tests;
