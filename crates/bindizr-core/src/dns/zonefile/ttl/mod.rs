//! Rewriting BIND's unit-suffixed TTLs into the decimal seconds RFC 1035,
//! Section 5.1 defines, ahead of the scanner that only takes those.

/// One line as the pre-pass reads it: the byte ranges of its tokens, and where
/// its comment begins. Quoted strings stay whole, so neither a space nor a `;`
/// inside one counts.
struct ScannedLine {
    tokens: Vec<(usize, usize)>,
    comment_at: usize,
}

/// Scan one zone-file line for tokens relevant to TTL resolution.
fn scan_line(line: &str) -> ScannedLine {
    let mut tokens = Vec::new();
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
                };
            }
            b' ' | b'\t' | b'\r' | b'\n' if !quoted => {
                if let Some(from) = start.take() {
                    tokens.push((from, index));
                }
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

        depth = depth + code.matches('(').count() - code.matches(')').count().min(depth);
    }

    out
}

/// The line with its TTL slots rewritten; everything else, whitespace
/// included, is copied byte for byte.
fn rewrite_ttl_slots(code: &str, tokens: &[(usize, usize)]) -> String {
    let Some(&(first, first_end)) = tokens.first() else {
        return code.to_string();
    };

    let slots: &[usize] = if code[..first].trim().is_empty() && code.starts_with('$') {
        // A directive's own argument, and only `$TTL`'s.
        if code[first..first_end].eq_ignore_ascii_case("$TTL") {
            &[1]
        } else {
            &[]
        }
    } else {
        // A record's owner is the first token only when the line starts at
        // column 0; an indented line begins at the TTL slot itself. Class and
        // TTL come in either order (RFC 1035, Section 5.1), so the next two
        // tokens are both candidates.
        if code.starts_with([' ', '\t']) {
            &[0, 1]
        } else {
            &[1, 2]
        }
    };

    let mut out = String::with_capacity(code.len());
    let mut copied = 0usize;
    for &slot in slots {
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
