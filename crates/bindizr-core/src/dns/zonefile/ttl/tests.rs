//! Which slots the rewrite may touch, and what it leaves byte for byte.

use super::{to_decimal_ttls, ttl_seconds};

/// Verify that unit suffixes convert to seconds.
#[test]
fn unit_suffixes_convert_to_seconds() {
    assert_eq!(ttl_seconds("1h"), Some(3600));
    assert_eq!(ttl_seconds("2d"), Some(172_800));
    assert_eq!(ttl_seconds("1w"), Some(604_800));
    assert_eq!(ttl_seconds("1h30m"), Some(5400));
    assert_eq!(ttl_seconds("30S"), Some(30));
}

/// Verify that anything that is not a TTL is left for the scanner.
#[test]
fn anything_that_is_not_a_ttl_is_left_for_the_scanner() {
    // Plain digits need no rewrite; the rest are not TTLs at all.
    assert_eq!(ttl_seconds("3600"), None);
    assert_eq!(ttl_seconds(""), None);
    assert_eq!(ttl_seconds("1y"), None);
    assert_eq!(ttl_seconds("h"), None);
    assert_eq!(ttl_seconds("1h2"), None);
    assert_eq!(ttl_seconds("www"), None);
}

/// Verify that the TTL slot is rewritten in either field order.
#[test]
fn the_ttl_slot_is_rewritten_in_either_field_order() {
    assert_eq!(
        to_decimal_ttls("www 1h IN A 192.0.2.1\n"),
        "www 3600 IN A 192.0.2.1\n"
    );
    assert_eq!(
        to_decimal_ttls("www IN 1h A 192.0.2.1\n"),
        "www IN 3600 A 192.0.2.1\n"
    );
    assert_eq!(to_decimal_ttls("$TTL 1h\n"), "$TTL 3600\n");
    // An indented line has no owner, so the slot starts at the first token.
    assert_eq!(
        to_decimal_ttls("  1h IN A 192.0.2.1\n"),
        "  3600 IN A 192.0.2.1\n"
    );
}

/// Verify that a TTL shaped token outside the slot is untouched.
#[test]
fn a_ttl_shaped_token_outside_the_slot_is_untouched() {
    // An owner may be named like a TTL, rdata may read like one, and a
    // comment is not code at all.
    for line in [
        "1h IN A 192.0.2.1\n",
        "txt IN TXT \"1h and 2d\"\n",
        "; 1h in a comment\n",
        "www 3600 IN A 192.0.2.1 ; 1h\n",
        "$ORIGIN 1h.example.com.\n",
    ] {
        assert_eq!(to_decimal_ttls(line), line);
    }
}

/// Verify that a continuation line keeps its RDATA.
#[test]
fn a_continuation_line_keeps_its_rdata() {
    // The TTL slot is behind us once the parentheses open, so the numbers
    // inside stay as written.
    let record = "sub 1h IN MX (\n  10\n  mail.example.com.\n)\n";

    assert_eq!(
        to_decimal_ttls(record),
        "sub 3600 IN MX (\n  10\n  mail.example.com.\n)\n"
    );
}
