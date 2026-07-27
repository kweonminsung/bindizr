//! SOA serial-number generation: a plain monotonic counter.
//!
//! Serials start at 1 and advance by exactly one on every zone mutation; the
//! "when" of a serial comes from `zone_soa_history.created_at`, not from the
//! serial itself. An explicit serial supplied at zone creation (e.g. when
//! taking over a zone whose secondaries already track a serial) simply becomes
//! the starting point and the counter continues from there. Stops at
//! `i32::MAX` because IXFR encodes serials as `u32` and rejects negatives, so
//! wrapping is not an option.

use crate::error::ServiceError;

/// Mutations a zone seeded with an explicit serial is guaranteed to have left.
const RESERVED_SERIAL_HEADROOM: i32 = 10_000_000;

/// Largest serial accepted as a zone's starting point, leaving
/// `RESERVED_SERIAL_HEADROOM` mutations before the counter reaches the ceiling.
pub const MAX_INITIAL_SERIAL: i32 = i32::MAX - RESERVED_SERIAL_HEADROOM;

/// Generate the next SOA serial: `None` (new zone) yields 1; `Some(s)` yields
/// `s + 1`. `i32::MAX` is an error rather than a saturating no-op, which would
/// repeat a serial silently — `zone_soa_history` upserts on `(zone_id, serial)`.
pub fn generate_serial(current_serial: Option<i32>) -> Result<i32, ServiceError> {
    match current_serial {
        Some(serial) if serial == i32::MAX => Err(ServiceError::zone_conflict(format!(
            "zone serial reached its maximum of {}, so the zone can no longer accept changes",
            i32::MAX
        ))),
        Some(serial) => Ok(serial + 1),
        None => Ok(1),
    }
}

/// Validate a client-supplied starting serial, returning it unchanged.
pub fn validate_initial_serial(serial: i32) -> Result<i32, ServiceError> {
    if serial < 1 {
        return Err(ServiceError::invalid_zone(format!(
            "serial {} must be a positive integer",
            serial
        )));
    }

    if serial > MAX_INITIAL_SERIAL {
        return Err(ServiceError::invalid_zone(format!(
            "serial {} must not exceed {}, leaving room for the counter to advance",
            serial, MAX_INITIAL_SERIAL
        )));
    }

    Ok(serial)
}

#[cfg(test)]
mod tests {
    use super::{MAX_INITIAL_SERIAL, generate_serial, validate_initial_serial};

    #[test]
    fn starts_at_one_for_new_zones() {
        assert_eq!(generate_serial(None).unwrap(), 1);
    }

    #[test]
    fn increments_by_one() {
        assert_eq!(generate_serial(Some(1)).unwrap(), 2);
        assert_eq!(generate_serial(Some(41)).unwrap(), 42);
    }

    #[test]
    fn continues_from_explicit_legacy_serials() {
        assert_eq!(generate_serial(Some(2023010101)).unwrap(), 2023010102);
    }

    #[test]
    fn rejects_mutations_once_the_serial_hits_i32_max() {
        assert!(generate_serial(Some(i32::MAX)).is_err());
    }

    #[test]
    fn advances_up_to_i32_max() {
        assert_eq!(generate_serial(Some(i32::MAX - 1)).unwrap(), i32::MAX);
    }

    #[test]
    fn accepts_serial_formats_carried_over_from_another_primary() {
        // The cap must still admit the formats a takeover carries over:
        // datestamp (YYYYMMDDnn) and unixtime.
        assert_eq!(validate_initial_serial(1).unwrap(), 1);
        assert_eq!(validate_initial_serial(2026072501).unwrap(), 2026072501);
        assert_eq!(validate_initial_serial(1753401600).unwrap(), 1753401600);
        assert_eq!(
            validate_initial_serial(MAX_INITIAL_SERIAL).unwrap(),
            MAX_INITIAL_SERIAL
        );
    }

    #[test]
    fn rejects_non_positive_serials() {
        assert!(validate_initial_serial(0).is_err());
        assert!(validate_initial_serial(-1).is_err());
    }

    #[test]
    fn rejects_serials_without_room_to_advance() {
        assert!(validate_initial_serial(MAX_INITIAL_SERIAL + 1).is_err());
        assert!(validate_initial_serial(i32::MAX).is_err());
    }

    #[test]
    fn accepted_serials_leave_the_counter_advancing() {
        let seeded = validate_initial_serial(MAX_INITIAL_SERIAL).unwrap();
        assert_eq!(
            generate_serial(Some(seeded)).unwrap(),
            MAX_INITIAL_SERIAL + 1
        );
    }
}
