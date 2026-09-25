//! SOA serial-number generation: a plain monotonic counter.
//!
//! Serials start at 1 and advance by exactly one on every zone mutation; the
//! "when" of a serial comes from `zone_versions.created_at`, not from the
//! serial itself. An explicit serial supplied at zone creation (e.g. when
//! taking over a zone whose secondaries already track a serial) simply becomes
//! the starting point and the counter continues from there. Stops at
//! `i32::MAX` because IXFR encodes serials as `u32` and rejects negatives, so
//! wrapping is not an option.

use bindizr_core::dns::serial_to_i32;

use crate::error::ServiceError;

/// Mutations a zone seeded with an explicit serial is guaranteed to have left.
const RESERVED_SERIAL_HEADROOM: i32 = 10_000_000;

/// Largest serial accepted as a zone's starting point, leaving
/// `RESERVED_SERIAL_HEADROOM` mutations before the counter reaches the ceiling.
const MAX_INITIAL_SERIAL: i32 = i32::MAX - RESERVED_SERIAL_HEADROOM;

/// Generate the next SOA serial: `None` (new zone) yields 1; `Some(s)` yields
/// `s + 1`. `i32::MAX` is an error rather than a saturating no-op, which would
/// repeat a serial silently — `zone_versions` upserts on `(zone_id, serial)`.
pub(crate) fn generate_serial(current_serial: Option<i32>) -> Result<i32, ServiceError> {
    match current_serial {
        Some(serial) if serial == i32::MAX => Err(ServiceError::zone_conflict(format!(
            "zone serial reached its maximum of {}, so the zone can no longer accept changes",
            i32::MAX
        ))),
        Some(serial) => Ok(serial + 1),
        None => Ok(1),
    }
}

/// Validate a client-supplied starting serial, returning it in stored form.
pub(crate) fn validate_initial_serial(serial: u32) -> Result<i32, ServiceError> {
    let serial = serial_to_i32(serial).map_err(ServiceError::invalid_zone_field)?;
    if serial < 1 {
        return Err(ServiceError::invalid_zone_field(format!(
            "serial {} must be a positive integer",
            serial
        )));
    }

    if serial > MAX_INITIAL_SERIAL {
        return Err(ServiceError::invalid_zone_field(format!(
            "serial {} must not exceed {}, leaving room for the counter to advance",
            serial, MAX_INITIAL_SERIAL
        )));
    }

    Ok(serial)
}

#[cfg(test)]
mod tests {
    use super::{MAX_INITIAL_SERIAL, generate_serial, validate_initial_serial};

    /// Verify that new zone serials start at one.
    #[test]
    fn starts_at_one_for_new_zones() {
        assert_eq!(generate_serial(None).unwrap(), 1);
    }

    /// Verify that a zone serial advances by one.
    #[test]
    fn increments_by_one() {
        assert_eq!(generate_serial(Some(1)).unwrap(), 2);
        assert_eq!(generate_serial(Some(41)).unwrap(), 42);
        // A datestamp serial carried over from another primary is only a
        // larger starting point.
        assert_eq!(generate_serial(Some(2023010101)).unwrap(), 2023010102);
    }

    /// Verify rejection of mutations after the serial reaches its storage limit.
    #[test]
    fn rejects_mutations_once_the_serial_hits_i32_max() {
        assert!(generate_serial(Some(i32::MAX)).is_err());
    }

    /// Verify that a serial can advance to the storage limit.
    #[test]
    fn advances_up_to_i32_max() {
        assert_eq!(generate_serial(Some(i32::MAX - 1)).unwrap(), i32::MAX);
    }

    /// Verify acceptance of valid serials imported from another primary.
    #[test]
    fn accepts_serial_formats_carried_over_from_another_primary() {
        // The cap must still admit the formats a takeover carries over:
        // datestamp (YYYYMMDDnn) and unixtime.
        assert_eq!(validate_initial_serial(1).unwrap(), 1);
        assert_eq!(validate_initial_serial(2026072501).unwrap(), 2026072501);
        assert_eq!(validate_initial_serial(1753401600).unwrap(), 1753401600);
        assert_eq!(
            validate_initial_serial(MAX_INITIAL_SERIAL as u32).unwrap(),
            MAX_INITIAL_SERIAL
        );
    }

    /// Verify rejection of a zero serial.
    #[test]
    fn rejects_a_zero_serial() {
        assert!(validate_initial_serial(0).is_err());
    }

    /// Verify that a serial past the stored range is refused as input.
    #[test]
    fn rejects_a_serial_beyond_the_stored_range() {
        assert!(validate_initial_serial(u32::MAX).is_err());
    }

    /// Verify rejection of serials that cannot advance.
    #[test]
    fn rejects_serials_without_room_to_advance() {
        assert!(validate_initial_serial((MAX_INITIAL_SERIAL + 1) as u32).is_err());
        assert!(validate_initial_serial(i32::MAX as u32).is_err());
    }

    /// Verify that accepted serials leave the counter advancing.
    #[test]
    fn accepted_serials_leave_the_counter_advancing() {
        let seeded = validate_initial_serial(MAX_INITIAL_SERIAL as u32).unwrap();
        assert_eq!(
            generate_serial(Some(seeded)).unwrap(),
            MAX_INITIAL_SERIAL + 1
        );
    }
}
