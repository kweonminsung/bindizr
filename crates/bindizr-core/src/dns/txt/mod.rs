use base64::Engine;

const RAW_TXT_RDATA_PREFIX: &str = "bindizr:txt-rdata:v1:";

#[derive(Debug, PartialEq, Eq)]
pub enum DecodedTxtValue {
    String(String),
    Segments(Vec<String>),
}

pub fn encode_raw_txt_rdata(rdata: &[u8]) -> String {
    format!(
        "{}{}",
        RAW_TXT_RDATA_PREFIX,
        base64::engine::general_purpose::STANDARD.encode(rdata)
    )
}

pub fn encode_txt_segments<'a, I>(segments: I) -> Result<String, String>
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
    Ok(encode_raw_txt_rdata(&rdata))
}

pub fn encode_txt_string(value: &str) -> String {
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
    encode_raw_txt_rdata(&rdata)
}

pub fn decode_raw_txt_rdata(value: &str) -> Option<Vec<u8>> {
    let encoded = value.strip_prefix(RAW_TXT_RDATA_PREFIX)?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
        .filter(|rdata| is_valid_txt_rdata(rdata))
}

pub fn decode_raw_txt_value(value: &str) -> Option<DecodedTxtValue> {
    let rdata = decode_raw_txt_rdata(value)?;
    if rdata.is_empty() {
        return None;
    }

    let mut pos = 0usize;
    let mut segments = Vec::new();

    while pos < rdata.len() {
        let chunk_len = rdata[pos] as usize;
        pos += 1;
        let chunk = std::str::from_utf8(&rdata[pos..pos + chunk_len]).ok()?;
        segments.push(chunk.to_string());
        pos += chunk_len;
    }

    match segments.as_slice() {
        [single] => Some(DecodedTxtValue::String(single.clone())),
        _ => Some(DecodedTxtValue::Segments(segments)),
    }
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

#[cfg(test)]
mod tests;
