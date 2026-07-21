//! SOA serial-number generation: a plain monotonic counter.
//!
//! Serials start at 1 and advance by exactly one on every zone mutation; the
//! "when" of a serial comes from `zone_soa_history.created_at`, not from the
//! serial itself. An explicit serial supplied at zone creation (e.g. when
//! taking over a zone whose secondaries already track a serial) simply becomes
//! the starting point and the counter continues from there. Saturates at
//! `i32::MAX` because IXFR encodes serials as `u32` and rejects negatives, so
//! wrapping is not an option.

/// Generate the next SOA serial: `None` (new zone) yields 1; `Some(s)` yields
/// `s + 1`, saturating at `i32::MAX`.
pub fn generate_serial(current_serial: Option<i32>) -> i32 {
    match current_serial {
        Some(serial) => serial.saturating_add(1),
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::generate_serial;

    #[test]
    fn starts_at_one_for_new_zones() {
        assert_eq!(generate_serial(None), 1);
    }

    #[test]
    fn increments_by_one() {
        assert_eq!(generate_serial(Some(1)), 2);
        assert_eq!(generate_serial(Some(41)), 42);
    }

    #[test]
    fn continues_from_explicit_legacy_serials() {
        assert_eq!(generate_serial(Some(2023010101)), 2023010102);
    }

    #[test]
    fn saturates_at_i32_max() {
        assert_eq!(generate_serial(Some(i32::MAX)), i32::MAX);
    }
}
