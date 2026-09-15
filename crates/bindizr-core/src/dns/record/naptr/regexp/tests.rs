use super::validate_naptr_regexp;

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
        assert!(err.contains(reason), "{regexp}: {err}");
    }
}
