//! The NAPTR regexp check BIND applies on receipt (`txt_valid_regex`). One
//! record BIND refuses fails the whole zone transfer it arrives in, so the
//! same rule has to hold when the record is stored.

#[cfg(test)]
mod tests;

/// Validate a NAPTR regexp as the substitution expression of RFC 3402,
/// Section 3.2, by the rules BIND's `txt_valid_regex` applies.
pub(crate) fn validate_naptr_regexp(regexp: &str) -> Result<(), String> {
    let Some((&delim, rest)) = regexp.as_bytes().split_first() else {
        return Ok(());
    };
    if delim.is_ascii_digit() || matches!(delim, b'\\' | b'i' | 0) {
        return Err(format!(
            "NAPTR regexp delimiter must not be a digit, a backslash, or a flag: {regexp}"
        ));
    }

    let mut regex = Vec::new();
    let mut backref = 0;
    let mut in_replacement = false;
    let mut in_flags = false;
    let mut bytes = rest.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == 0 {
            return Err("NAPTR regexp must not contain a NUL byte".to_string());
        }
        if byte == delim {
            if !in_replacement {
                in_replacement = true;
            } else if !in_flags {
                in_flags = true;
            } else {
                return Err(format!(
                    "NAPTR regexp has more than three delimiters: {regexp}"
                ));
            }
            continue;
        }
        // Flags are not escaped, so a backslash there is just an unknown flag.
        if in_flags {
            if byte == b'i' {
                continue;
            }
            return Err(format!("NAPTR regexp flags may only be 'i': {regexp}"));
        }
        if !in_replacement {
            regex.push(byte);
        }
        if byte == b'\\' {
            let Some(escaped) = bytes.next() else {
                return Err(format!("NAPTR regexp ends in a dangling escape: {regexp}"));
            };
            if escaped == 0 {
                return Err("NAPTR regexp must not contain a NUL byte".to_string());
            }
            if in_replacement {
                match escaped {
                    b'0' => {
                        return Err(format!(
                            "NAPTR regexp replacement must not refer to \\0: {regexp}"
                        ));
                    }
                    b'1'..=b'9' => backref = backref.max(usize::from(escaped - b'0')),
                    _ => {}
                }
            } else {
                regex.push(escaped);
            }
        }
    }
    if !in_flags {
        return Err(format!(
            "NAPTR regexp must be '<delim>regex<delim>replacement<delim>flags' (RFC 3402, Section 3.2): {regexp}"
        ));
    }

    let groups = validate_ere(&regex).map_err(|reason| {
        format!("NAPTR regexp regular expression is invalid ({reason}): {regexp}")
    })?;
    if backref > groups {
        return Err(format!(
            "NAPTR regexp replacement refers to \\{backref} but the regular expression has {groups} groups: {regexp}"
        ));
    }
    Ok(())
}

/// The character classes of the C locale.
const CHARACTER_CLASSES: [&[u8]; 12] = [
    b":alnum:",
    b":digit:",
    b":punct:",
    b":alpha:",
    b":graph:",
    b":space:",
    b":blank:",
    b":lower:",
    b":upper:",
    b":cntrl:",
    b":print:",
    b":xdigit:",
];

/// Where the validator stands inside the expression.
#[derive(PartialEq)]
enum State {
    Outside,
    Bracket,
    Bound,
    CollatingElement,
    EquivalenceClass,
    CharacterClass,
}

/// Validate a POSIX extended regular expression in the C locale and report
/// its subexpression count, step for step as BIND's `isc_regex_validate` does.
fn validate_ere(regex: &[u8]) -> Result<usize, &'static str> {
    if regex.is_empty() {
        return Err("empty string");
    }
    // Reading past the end yields the NUL terminator BIND's C string has.
    let at = |index: usize| regex.get(index).copied().unwrap_or(0);

    let mut state = State::Outside;
    let mut seen_comma = false;
    let mut seen_high = false;
    let mut seen_char = false;
    let mut seen_ec = false;
    let mut seen_ce = false;
    let mut have_atom = false;
    let mut group = 0usize;
    let mut range = 0u8;
    let mut sub = 0usize;
    let mut empty_ok = false;
    let mut neg = false;
    let mut was_multiple = false;
    let mut low = 0u32;
    let mut high = 0u32;
    let mut class_start = 0usize;
    let mut range_start = 0u16;

    let mut i = 0;
    while at(i) != 0 {
        match state {
            State::Outside => match at(i) {
                b'\\' => {
                    i += 1;
                    match at(i) {
                        b'1'..=b'9' => {
                            if usize::from(at(i) - b'0') > sub {
                                return Err("bad back reference");
                            }
                        }
                        0 => return Err("escaped end-of-string"),
                        _ => {}
                    }
                    have_atom = true;
                    was_multiple = false;
                    i += 1;
                }
                b'[' => {
                    i += 1;
                    neg = false;
                    was_multiple = false;
                    seen_char = false;
                    state = State::Bracket;
                }
                b'{' if at(i + 1).is_ascii_digit() => {
                    if !have_atom {
                        return Err("no atom");
                    }
                    if was_multiple {
                        return Err("was multiple");
                    }
                    seen_comma = false;
                    seen_high = false;
                    low = 0;
                    high = 0;
                    state = State::Bound;
                    have_atom = true;
                    was_multiple = true;
                    i += 1;
                }
                b'(' => {
                    have_atom = false;
                    was_multiple = false;
                    empty_ok = true;
                    group += 1;
                    sub += 1;
                    i += 1;
                }
                b')' => {
                    if group != 0 && !have_atom && !empty_ok {
                        return Err("empty alternative");
                    }
                    have_atom = true;
                    was_multiple = false;
                    group = group.saturating_sub(1);
                    i += 1;
                }
                b'|' => {
                    if !have_atom {
                        return Err("no atom");
                    }
                    have_atom = false;
                    empty_ok = false;
                    was_multiple = false;
                    i += 1;
                }
                b'^' | b'$' => {
                    have_atom = true;
                    was_multiple = true;
                    i += 1;
                }
                b'+' | b'*' | b'?' => {
                    if was_multiple {
                        return Err("was multiple");
                    }
                    if !have_atom {
                        return Err("no atom");
                    }
                    have_atom = true;
                    was_multiple = true;
                    i += 1;
                }
                // `.`, `}`, a `{` without a bound, and every other byte are literals.
                _ => {
                    have_atom = true;
                    was_multiple = false;
                    i += 1;
                }
            },
            State::Bound => match at(i) {
                digit @ b'0'..=b'9' => {
                    let digit = u32::from(digit - b'0');
                    if seen_comma {
                        seen_high = true;
                        high = high * 10 + digit;
                        if high > 255 {
                            return Err("upper bound too big");
                        }
                    } else {
                        low = low * 10 + digit;
                        if low > 255 {
                            return Err("lower bound too big");
                        }
                    }
                    i += 1;
                }
                b',' => {
                    if seen_comma {
                        return Err("multiple commas");
                    }
                    seen_comma = true;
                    i += 1;
                }
                b'}' => {
                    if seen_high && low > high {
                        return Err("bad parse bound");
                    }
                    state = State::Outside;
                    i += 1;
                }
                _ => return Err("non digit/comma"),
            },
            State::Bracket => match at(i) {
                b'^' if !seen_char && !neg => {
                    neg = true;
                    i += 1;
                }
                b'-' if range != 2 && seen_char => {
                    if range == 1 {
                        return Err("bad range");
                    }
                    range = 2;
                    i += 1;
                }
                b'[' => {
                    i += 1;
                    match at(i) {
                        b'.' => {
                            range = range.saturating_sub(1);
                            i += 1;
                            state = State::CollatingElement;
                            seen_ce = false;
                        }
                        b'=' => {
                            if range == 2 {
                                return Err("equivalence class in range");
                            }
                            i += 1;
                            state = State::EquivalenceClass;
                            seen_ec = false;
                        }
                        b':' => {
                            if range == 2 {
                                return Err("character class in range");
                            }
                            class_start = i;
                            i += 1;
                            state = State::CharacterClass;
                        }
                        _ => {}
                    }
                    seen_char = true;
                }
                b']' if seen_char => {
                    i += 1;
                    range = 0;
                    have_atom = true;
                    state = State::Outside;
                }
                b']' if at(i + 1) == 0 => return Err("unfinished brace"),
                // A leading `]`, a `^` past the start, or a `-` at an edge is
                // a member of the set.
                byte => {
                    seen_char = true;
                    if range == 2 && u16::from(byte) < range_start {
                        return Err("out of order range");
                    }
                    range = range.saturating_sub(1);
                    range_start = u16::from(byte);
                    i += 1;
                }
            },
            State::CollatingElement => match at(i) {
                b'.' => {
                    i += 1;
                    if at(i) == b']' {
                        if !seen_ce {
                            return Err("empty ce");
                        }
                        i += 1;
                        state = State::Bracket;
                    } else {
                        range_start = if seen_ce { 256 } else { u16::from(b'.') };
                        seen_ce = true;
                    }
                }
                byte => {
                    range_start = if seen_ce { 256 } else { u16::from(byte) };
                    seen_ce = true;
                    i += 1;
                }
            },
            State::EquivalenceClass => match at(i) {
                b'=' => {
                    i += 1;
                    if at(i) == b']' {
                        if !seen_ec {
                            return Err("no ec");
                        }
                        i += 1;
                        state = State::Bracket;
                    } else {
                        seen_ec = true;
                    }
                }
                _ => {
                    seen_ec = true;
                    i += 1;
                }
            },
            State::CharacterClass => {
                if at(i) == b':' {
                    i += 1;
                    if at(i) == b']' {
                        if !CHARACTER_CLASSES.contains(&&regex[class_start..i]) {
                            return Err("unknown cc");
                        }
                        i += 1;
                        state = State::Bracket;
                    }
                } else {
                    i += 1;
                }
            }
        }
    }

    if group != 0 {
        return Err("group open");
    }
    if state != State::Outside {
        return Err("incomplete");
    }
    if !have_atom {
        return Err("no atom");
    }
    Ok(sub)
}
