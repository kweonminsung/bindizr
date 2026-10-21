//! Adapt native WKS text to the generic wire syntax understood by `domain`.

use std::ops::Range;

use domain::base::iana::Rtype;
use thiserror::Error;

use crate::dns::record::{EncodeRdataError, ParseRecordValueError, WksRecordValue};

/// Why native WKS text could not be prepared for the zone-file parser.
#[derive(Debug, Error)]
pub(crate) enum RewriteNativeRecordsError {
    #[error("unexpected ')' in zone file")]
    UnexpectedClosingParenthesis,
    #[error("unterminated parentheses, quote, or escape in zone file")]
    UnterminatedEntry,
    #[error("{line}: WKS: {source}")]
    Value {
        line: usize,
        #[source]
        source: ParseRecordValueError,
    },
    #[error("{line}: WKS: {source}")]
    Rdata {
        line: usize,
        #[source]
        source: EncodeRdataError,
    },
}

/// Rewrite native WKS records in generic wire syntax, preserving other records and source lines.
pub(crate) fn rewrite_native_records(content: &str) -> Result<String, RewriteNativeRecordsError> {
    let mut output = String::with_capacity(content.len());
    let mut fields = Vec::new();
    let mut entry_start = 0;
    let mut token_start = None;
    let mut quoted = false;
    let mut escaped = false;
    let mut comment = false;
    let mut depth = 0usize;
    for (index, byte) in content.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if comment {
            if byte != b'\n' {
                continue;
            }
            comment = false;
        } else if byte == b'\\' {
            token_start.get_or_insert(index);
            escaped = true;
            continue;
        } else if byte == b'"' {
            token_start.get_or_insert(index);
            quoted = !quoted;
            continue;
        } else if !quoted && byte == b';' {
            if let Some(start) = token_start.take() {
                fields.push(start..index);
            }
            comment = true;
            continue;
        }
        if quoted {
            continue;
        }
        if byte.is_ascii_whitespace() || matches!(byte, b'(' | b')') {
            if let Some(start) = token_start.take() {
                fields.push(start..index);
            }
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or(RewriteNativeRecordsError::UnexpectedClosingParenthesis)?;
                }
                _ => {}
            }
            if byte == b'\n' && depth == 0 {
                append_entry(&mut output, content, entry_start..index + 1, &fields)?;
                fields.clear();
                entry_start = index + 1;
            }
        } else {
            token_start.get_or_insert(index);
        }
    }
    if depth != 0 || quoted || escaped {
        return Err(RewriteNativeRecordsError::UnterminatedEntry);
    }
    if let Some(start) = token_start {
        fields.push(start..content.len());
    }
    append_entry(&mut output, content, entry_start..content.len(), &fields)?;
    Ok(output)
}

/// Convert a WKS entry without treating type-like text inside another record as a header.
fn append_entry(
    output: &mut String,
    content: &str,
    entry: Range<usize>,
    fields: &[Range<usize>],
) -> Result<(), RewriteNativeRecordsError> {
    let original = &content[entry.clone()];
    let owner_fields = usize::from(!original.starts_with(char::is_whitespace));
    let is_directive = fields
        .first()
        .is_some_and(|field| content[field.clone()].starts_with('$'));
    let record_type = fields
        .iter()
        .enumerate()
        .skip(owner_fields)
        .take(3)
        .find_map(|(index, field)| {
            content[field.clone()]
                .parse::<Rtype>()
                .ok()
                .map(|rtype| (index, rtype))
        });
    let Some((type_index, Rtype::WKS)) = record_type.filter(|_| !is_directive) else {
        output.push_str(original);
        return Ok(());
    };
    let data_fields = &fields[type_index + 1..];
    if data_fields
        .first()
        .is_some_and(|field| &content[field.clone()] == r"\#")
    {
        output.push_str(original);
        return Ok(());
    }
    let value = data_fields
        .iter()
        .map(|field| &content[field.clone()])
        .collect::<Vec<_>>()
        .join(" ");
    let line = || {
        content[..entry.start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1
    };
    let parsed =
        WksRecordValue::parse(&value).map_err(|source| RewriteNativeRecordsError::Value {
            line: line(),
            source,
        })?;
    let rdata = parsed
        .to_rdata()
        .map_err(|source| RewriteNativeRecordsError::Rdata {
            line: line(),
            source,
        })?;
    let data_start = fields[type_index].end;
    output.push_str(&content[entry.start..data_start]);
    output.push_str(&format!(
        r" \# {} {}",
        rdata.as_bytes().len(),
        hex::encode_upper(rdata.as_bytes())
    ));
    output.extend(std::iter::repeat_n(
        '\n',
        content[data_start..entry.end]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count(),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    /// Preserve the WKS parse cause until the zone-file result renders its diagnostic.
    #[test]
    fn rewrite_native_records_preserves_value_error_and_source_line() {
        let content = "@ IN NS ns.example.com.\nhost IN WKS 192.0.2.1 256 80\n";
        let error = rewrite_native_records(content).unwrap_err();
        let source = error.source().unwrap();
        assert!(source.downcast_ref::<ParseRecordValueError>().is_some());
        assert_eq!(error.to_string(), format!("2: WKS: {source}"));
        let parsed = crate::dns::zonefile::ParsedZoneFile::parse(
            content,
            &crate::dns::name::ZoneName::parse("example.com").unwrap(),
            crate::dns::Ttl::from_secs(300),
        );
        assert_eq!(parsed.errors, vec![error.to_string()]);
    }

    /// Preserve other records, inherited owners, and line numbers around multiline WKS.
    #[test]
    fn rewrite_native_records_preserves_other_records_and_multiline_wks() {
        let content = "$ORIGIN example.com.\n@ IN NS ns.example.com.\nhost IN WKS 192.0.2.1 TCP ( 0 ; services\n 7 8 )\n 300 WKS 192.0.2.2 UDP 53\ntext IN TXT \"WKS\" \"192.0.2.1 6 80\"\nWKS IN A 192.0.2.8\n";
        let normalized = rewrite_native_records(content).unwrap();
        assert_eq!(normalized.lines().count(), content.lines().count());
        assert!(normalized.contains(r"host IN WKS \# 7 C0000201068180"));
        assert!(
            normalized.contains("text IN TXT \"WKS\" \"192.0.2.1 6 80\"\nWKS IN A 192.0.2.8\n")
        );
        let parsed = crate::dns::zonefile::ParsedZoneFile::parse(
            content,
            &crate::dns::name::ZoneName::parse("example.com").unwrap(),
            crate::dns::Ttl::from_secs(300),
        );
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        assert_eq!(parsed.records.len(), 5);
        assert_eq!(
            parsed.records[1].record_type,
            crate::model::record::RecordType::Wks
        );
        assert_eq!(parsed.records[2].owner_fqdn, "host.example.com.");
    }

    /// Generic WKS data and escaped or quoted type-like text remain untouched.
    #[test]
    fn rewrite_native_records_preserves_generic_wks_and_escaped_tokens() {
        for content in [
            r"host IN WKS \# 6 C00002010680",
            r#"host IN TXT "a\" WKS 192.0.2.1 TCP 80""#,
            r"WKS\.host IN A 192.0.2.1",
        ] {
            assert_eq!(rewrite_native_records(content).unwrap(), content);
        }
        for content in [
            "host IN WKS 192.0.2.1 256 80",
            "host IN WKS ( 192.0.2.1 TCP 80",
            "host IN WKS 192.0.2.1 TCP 80 )",
        ] {
            assert!(rewrite_native_records(content).is_err());
        }
    }
}
