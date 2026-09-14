//! Rewriting BIND's unit-suffixed TTLs into the decimal seconds RFC 1035,
//! Section 5.1 defines, ahead of the scanner that only takes those.

/// One line as the pre-pass reads it: the byte ranges of its tokens, and where
/// its comment begins. Quoted strings stay whole, so neither a space nor a `;`
/// inside one counts.
struct ScannedLine {
    tokens: Vec<(usize, usize)>,
    comment_at: usize,
    /// The grouping parentheses of RFC 1035, Section 5.1, in order. Only the
    /// ones outside quotes: a `(` inside a TXT string is data.
    parens: Vec<u8>,
}

/// Scan one zone-file line for tokens relevant to TTL resolution.
fn scan_line(line: &str) -> ScannedLine {
    let mut tokens = Vec::new();
    let mut parens = Vec::new();
    let mut start = None;
    let mut quoted = false;
    let mut escaped = false;

    for (index, byte) in line.bytes().enumerate() {
        match byte {
            _ if escaped => escaped = false,
            b'\\' => escaped = true,
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                if let Some(from) = start.take() {
                    tokens.push((from, index));
                }
                return ScannedLine {
                    tokens,
                    comment_at: index,
                    parens,
                };
            }
            b' ' | b'\t' | b'\r' | b'\n' if !quoted => {
                if let Some(from) = start.take() {
                    tokens.push((from, index));
                }
            }
            b'(' | b')' if !quoted => {
                parens.push(byte);
                start = start.or(Some(index));
            }
            _ => start = start.or(Some(index)),
        }
    }
    if let Some(from) = start {
        tokens.push((from, line.len()));
    }

    ScannedLine {
        tokens,
        comment_at: line.len(),
        parens,
    }
}

/// BIND writes TTLs as `1h` or `2d30m` and every serving implementation takes
/// them, but one such token fails the whole file here. Rewrite them in place,
/// touching only the slots a TTL may occupy.
pub(crate) fn to_decimal_ttls(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut depth = 0usize;

    for line in content.split_inclusive('\n') {
        let scanned = scan_line(line);
        let code = &line[..scanned.comment_at];

        if depth == 0 {
            out.push_str(&rewrite_ttl_slots(code, &scanned.tokens));
        } else {
            // Inside parentheses the record's TTL slot is already behind us.
            out.push_str(code);
        }
        out.push_str(&line[scanned.comment_at..]);

        // Folded in order, so a group opened and closed on one line nets out.
        for paren in scanned.parens {
            depth = match paren {
                b'(' => depth + 1,
                _ => depth.saturating_sub(1),
            };
        }
    }

    out
}

/// The line with its TTL slots rewritten; everything else, whitespace
/// included, is copied byte for byte.
fn rewrite_ttl_slots(code: &str, tokens: &[(usize, usize)]) -> String {
    let Some(&(first, first_end)) = tokens.first() else {
        return code.to_string();
    };

    let slots: Vec<usize> = if code[..first].trim().is_empty() && code.starts_with('$') {
        // A directive's own argument, and only `$TTL`'s.
        if code[first..first_end].eq_ignore_ascii_case("$TTL") {
            vec![1]
        } else {
            Vec::new()
        }
    } else {
        // A record's owner is the first token only when the line starts at
        // column 0; an indented line begins at the TTL slot itself. Class and
        // TTL come in either order before the type (RFC 1035, Section 5.1),
        // and the scan stops at the type: past it every token is RDATA, where
        // `1h` is a name a CNAME points at, not a TTL.
        let start = if code.starts_with([' ', '\t']) { 0 } else { 1 };
        (start..tokens.len())
            .take_while(|&slot| {
                let (from, to) = tokens[slot];
                let token = &code[from..to];
                is_class(token) || ttl_seconds(token).is_some()
            })
            .collect()
    };

    let mut out = String::with_capacity(code.len());
    let mut copied = 0usize;
    for slot in slots {
        let Some(&(from, to)) = tokens.get(slot) else {
            continue;
        };
        let Some(seconds) = ttl_seconds(&code[from..to]) else {
            continue;
        };

        out.push_str(&code[copied..from]);
        out.push_str(&seconds.to_string());
        copied = to;
    }
    out.push_str(&code[copied..]);

    out
}

/// A unit-suffixed TTL in seconds: `<digits><unit>` repeated, over seconds,
/// minutes, hours, days, and weeks. `None` for plain digits, which need no
/// rewrite, and for anything else, which is not a TTL.
/// Whether the token is a CLASS rather than a TTL, so the scan may step over
/// it and keep looking (RFC 1035, Section 5.1; RFC 3597, Section 5 for
/// `CLASS<n>`).
fn is_class(token: &str) -> bool {
    matches!(
        token.to_ascii_uppercase().as_str(),
        "IN" | "CH" | "CS" | "HS"
    ) || token
        .strip_prefix("CLASS")
        .or_else(|| token.strip_prefix("class"))
        .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

fn ttl_seconds(token: &str) -> Option<u32> {
    if token.is_empty() || token.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let mut total = 0u32;
    let mut digits = String::new();
    for c in token.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }

        let unit = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return None,
        };
        let count: u32 = digits.parse().ok()?;
        digits.clear();
        total = total.checked_add(count.checked_mul(unit)?)?;
    }

    digits.is_empty().then_some(total)
}

#[cfg(test)]
mod tests;
