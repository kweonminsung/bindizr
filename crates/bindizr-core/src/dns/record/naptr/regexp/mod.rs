//! The NAPTR regexp check BIND applies on receipt (`txt_valid_regex`). One
//! record BIND refuses fails the whole zone transfer it arrives in, so the
//! same rule has to hold when the record is stored.

use thiserror::Error;

/// Why BIND would refuse a NAPTR regexp, with the expression it refuses.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NaptrRegexpError {
    #[error("NAPTR regexp delimiter must not be a digit, a backslash, or a flag: {regexp}")]
    Delimiter { regexp: String },
    #[error("NAPTR regexp must not contain a NUL byte")]
    Nul,
    #[error("NAPTR regexp has more than three delimiters: {regexp}")]
    ExtraDelimiter { regexp: String },
    #[error("NAPTR regexp flags may only be 'i': {regexp}")]
    Flags { regexp: String },
    #[error("NAPTR regexp ends in a dangling escape: {regexp}")]
    DanglingEscape { regexp: String },
    #[error("NAPTR regexp replacement must not refer to \\0: {regexp}")]
    BackrefZero { regexp: String },
    #[error(
        "NAPTR regexp must be '<delim>regex<delim>replacement<delim>flags' (RFC 3402, Section 3.2): {regexp}"
    )]
    Shape { regexp: String },
    #[error("NAPTR regexp regular expression is invalid ({source}): {regexp}")]
    Ere {
        regexp: String,
        #[source]
        source: EreError,
    },
    #[error(
        "NAPTR regexp replacement refers to \\{backref} but the regular expression has {groups} groups: {regexp}"
    )]
    Backref {
        backref: usize,
        groups: usize,
        regexp: String,
    },
}

/// Why the regular expression half is not a valid POSIX ERE, in the words
/// BIND's validator uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EreError {
    #[error("bad back reference")]
    BadBackReference,
    #[error("bad parse bound")]
    BadParseBound,
    #[error("bad range")]
    BadRange,
    #[error("character class in range")]
    CharacterClassInRange,
    #[error("empty alternative")]
    EmptyAlternative,
    #[error("empty ce")]
    EmptyCe,
    #[error("empty string")]
    EmptyString,
    #[error("equivalence class in range")]
    EquivalenceClassInRange,
    #[error("escaped end-of-string")]
    EscapedEndOfString,
    #[error("group open")]
    GroupOpen,
    #[error("incomplete")]
    Incomplete,
    #[error("lower bound too big")]
    LowerBoundTooBig,
    #[error("multiple commas")]
    MultipleCommas,
    #[error("no atom")]
    NoAtom,
    #[error("no ec")]
    NoEc,
    #[error("non digit/comma")]
    NonDigitComma,
    #[error("out of order range")]
    OutOfOrderRange,
    #[error("unfinished brace")]
    UnfinishedBrace,
    #[error("unknown cc")]
    UnknownCc,
    #[error("upper bound too big")]
    UpperBoundTooBig,
    #[error("was multiple")]
    WasMultiple,
}

/// Validate a NAPTR regexp as the substitution expression of RFC 3402,
/// Section 3.2, by the rules BIND's `txt_valid_regex` applies.
pub(crate) fn validate_naptr_regexp(regexp: &str) -> Result<(), NaptrRegexpError> {
    let Some((&delim, rest)) = regexp.as_bytes().split_first() else {
        return Ok(());
    };
    if delim.is_ascii_digit() || matches!(delim, b'\\' | b'i' | 0) {
        return Err(NaptrRegexpError::Delimiter {
            regexp: regexp.to_string(),
        });
    }

    let mut regex = Vec::new();
    let mut backref = 0;
    let mut in_replacement = false;
    let mut in_flags = false;
    let mut bytes = rest.iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == 0 {
            return Err(NaptrRegexpError::Nul);
        }
        if byte == delim {
            if !in_replacement {
                in_replacement = true;
            } else if !in_flags {
                in_flags = true;
            } else {
                return Err(NaptrRegexpError::ExtraDelimiter {
                    regexp: regexp.to_string(),
                });
            }
            continue;
        }
        // Flags are not escaped, so a backslash there is just an unknown flag.
        if in_flags {
            if byte == b'i' {
                continue;
            }
            return Err(NaptrRegexpError::Flags {
                regexp: regexp.to_string(),
            });
        }
        if !in_replacement {
            regex.push(byte);
        }
        if byte == b'\\' {
            let Some(escaped) = bytes.next() else {
                return Err(NaptrRegexpError::DanglingEscape {
                    regexp: regexp.to_string(),
                });
            };
            if escaped == 0 {
                return Err(NaptrRegexpError::Nul);
            }
            if in_replacement {
                match escaped {
                    b'0' => {
                        return Err(NaptrRegexpError::BackrefZero {
                            regexp: regexp.to_string(),
                        });
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
        return Err(NaptrRegexpError::Shape {
            regexp: regexp.to_string(),
        });
    }

    let groups = validate_ere(&regex).map_err(|source| NaptrRegexpError::Ere {
        regexp: regexp.to_string(),
        source,
    })?;
    if backref > groups {
        return Err(NaptrRegexpError::Backref {
            backref,
            groups,
            regexp: regexp.to_string(),
        });
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
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
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
fn validate_ere(regex: &[u8]) -> Result<usize, EreError> {
    if regex.is_empty() {
        return Err(EreError::EmptyString);
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
                                return Err(EreError::BadBackReference);
                            }
                        }
                        0 => return Err(EreError::EscapedEndOfString),
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
                        return Err(EreError::NoAtom);
                    }
                    if was_multiple {
                        return Err(EreError::WasMultiple);
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
                        return Err(EreError::EmptyAlternative);
                    }
                    have_atom = true;
                    was_multiple = false;
                    group = group.saturating_sub(1);
                    i += 1;
                }
                b'|' => {
                    if !have_atom {
                        return Err(EreError::NoAtom);
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
                        return Err(EreError::WasMultiple);
                    }
                    if !have_atom {
                        return Err(EreError::NoAtom);
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
                            return Err(EreError::UpperBoundTooBig);
                        }
                    } else {
                        low = low * 10 + digit;
                        if low > 255 {
                            return Err(EreError::LowerBoundTooBig);
                        }
                    }
                    i += 1;
                }
                b',' => {
                    if seen_comma {
                        return Err(EreError::MultipleCommas);
                    }
                    seen_comma = true;
                    i += 1;
                }
                b'}' => {
                    if seen_high && low > high {
                        return Err(EreError::BadParseBound);
                    }
                    state = State::Outside;
                    i += 1;
                }
                _ => return Err(EreError::NonDigitComma),
            },
            State::Bracket => match at(i) {
                b'^' if !seen_char && !neg => {
                    neg = true;
                    i += 1;
                }
                b'-' if range != 2 && seen_char => {
                    if range == 1 {
                        return Err(EreError::BadRange);
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
                                return Err(EreError::EquivalenceClassInRange);
                            }
                            i += 1;
                            state = State::EquivalenceClass;
                            seen_ec = false;
                        }
                        b':' => {
                            if range == 2 {
                                return Err(EreError::CharacterClassInRange);
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
                b']' if at(i + 1) == 0 => return Err(EreError::UnfinishedBrace),
                // A leading `]`, a `^` past the start, or a `-` at an edge is
                // a member of the set.
                byte => {
                    seen_char = true;
                    if range == 2 && u16::from(byte) < range_start {
                        return Err(EreError::OutOfOrderRange);
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
                            return Err(EreError::EmptyCe);
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
                            return Err(EreError::NoEc);
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
                            return Err(EreError::UnknownCc);
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
        return Err(EreError::GroupOpen);
    }
    if state != State::Outside {
        return Err(EreError::Incomplete);
    }
    if !have_atom {
        return Err(EreError::NoAtom);
    }
    Ok(sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the substitution expressions BIND accepts are accepted.
    #[test]
    fn accepts_the_substitution_expressions_bind_accepts() {
        for regexp in [
            // An empty regexp is the common case (RFC 3403, Section 4.1).
            "",
            "!^.*$!sip:info@example.com!",
            "!^.*$!tel:+1!",
            "!^.*$!sip:info@example.com!i",
            r"!^\+46(.*)$!ldap://ldap.se/cn=0\1!",
            // An escaped delimiter is data (RFC 3402, Section 3.2).
            r"!a\!b!c!",
            // Any non-digit delimiter; bracket expressions, classes, and bounds.
            "/^[[:alpha:]]+$/x/",
            r"!(a|b)?c{2,3}!\1!",
            r"!^[^@]+@example\.com$!x!i",
            "!a{3}!b!",
            "!a{3,}!b!",
            "![-a-z0-9]!b!",
            "![]a]!b!",
            "![[.a.]-z]!b!",
            "![[=a=]]!b!",
            // Multi-byte text is a run of literal bytes.
            "!caf\u{e9}!th\u{e9}!",
        ] {
            validate_naptr_regexp(regexp).unwrap_or_else(|e| panic!("{regexp} was rejected: {e}"));
        }
    }

    /// Verify that the substitution expressions BIND refuses are refused, each
    /// for the reason BIND gives.
    #[test]
    fn refuses_the_substitution_expressions_bind_refuses() {
        for (regexp, reason) in [
            // No substitution expression at all.
            (
                "garbage",
                "must be '<delim>regex<delim>replacement<delim>flags'",
            ),
            (
                "!^.*$!x",
                "must be '<delim>regex<delim>replacement<delim>flags'",
            ),
            // NUL anywhere, including inside an escape.
            ("!^.*$!sip:a\u{0}b@example.com!", "NUL"),
            ("!^.*$!sip:a\\\u{0}b!", "NUL"),
            // Delimiters a digit, a backslash, or a flag would confuse.
            ("1a1b1", "delimiter"),
            (r"\a\b\", "delimiter"),
            ("iaibi", "delimiter"),
            ("!^.*$!x!i!", "more than three delimiters"),
            ("!^.*$!x!x", "flags may only be 'i'"),
            ("!^.*$!x\\", "dangling escape"),
            // Backreferences the regular expression cannot satisfy.
            (r"!^.*$!\0!", r"must not refer to \0"),
            (
                r"!^.*$!\1!",
                r"refers to \1 but the regular expression has 0 groups",
            ),
            (
                r"!(a)(b)!\3!",
                r"refers to \3 but the regular expression has 2 groups",
            ),
            // POSIX ERE errors inside the regular expression.
            ("!a**!b!", "was multiple"),
            ("!*a!b!", "no atom"),
            ("!a|!b!", "no atom"),
            ("!(a|)!b!", "empty alternative"),
            ("!(a!b!", "group open"),
            ("![a!b!", "incomplete"),
            ("!a{3,2}!b!", "bad parse bound"),
            ("!a{300}!b!", "lower bound too big"),
            ("!a{1,2,3}!b!", "multiple commas"),
            ("!a{1x}!b!", "non digit/comma"),
            ("![z-a]!b!", "out of order range"),
            ("![a-b-c]!b!", "bad range"),
            ("![[:foo:]]!b!", "unknown cc"),
            ("![[.a.]-[:alpha:]]!b!", "character class in range"),
            ("![[..]]!b!", "empty ce"),
            ("![[==]]!b!", "no ec"),
            ("![]!b!", "unfinished brace"),
        ] {
            let err = validate_naptr_regexp(regexp).expect_err(&format!("{regexp} was accepted"));
            assert!(err.to_string().contains(reason), "{regexp}: {err}");
        }
    }
}
