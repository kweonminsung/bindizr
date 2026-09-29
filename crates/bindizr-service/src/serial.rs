//! SOA serial-number generation: a plain monotonic counter.
//!
//! Serials start at 1 and advance by exactly one on every zone mutation; the
//! "when" of a serial comes from `zone_versions.created_at`, not from the
//! serial itself. An explicit serial supplied at zone creation (e.g. when
//! taking over a zone whose secondaries already track a serial) simply becomes
//! the starting point and the counter continues from there. Stops at
//! `i32::MAX` because IXFR encodes serials as `u32` and rejects negatives, so
//! wrapping is not an option.

use bindizr_core::dns::Serial;

use crate::error::ServiceError;

/// Mutations a zone seeded with an explicit serial is guaranteed to have left.
const RESERVED_SERIAL_HEADROOM: u32 = 10_000_000;

/// Largest serial accepted as a zone's starting point, leaving
/// `RESERVED_SERIAL_HEADROOM` mutations before the counter reaches the ceiling.
const MAX_INITIAL_SERIAL: u32 = Serial::MAX_STORED.as_u32() - RESERVED_SERIAL_HEADROOM;

/// Generate the next SOA serial: `None` (new zone) yields 1; `Some(s)` yields
/// `s + 1`. The stored ceiling is an error rather than a saturating no-op,
/// which would repeat a serial silently — `zone_versions` upserts on
/// `(zone_id, serial)`.
pub(crate) fn generate_serial(current_serial: Option<Serial>) -> Result<Serial, ServiceError> {
    match current_serial {
        Some(serial) => serial.next().ok_or_else(|| {
            ServiceError::zone_conflict(format!(
                "zone serial reached its maximum of {}, so the zone can no longer accept changes",
                Serial::MAX_STORED
            ))
        }),
        None => Ok(Serial::from(1)),
    }
}

/// A version serial as a request names it, refused as invalid input past the
/// stored range, since no row could hold it.
pub(crate) fn validate_stored_serial(serial: Serial) -> Result<Serial, ServiceError> {
    i32::try_from(serial).map_err(ServiceError::invalid_input)?;
    Ok(serial)
}

/// Validate a client-supplied starting serial.
pub(crate) fn validate_initial_serial(serial: Serial) -> Result<Serial, ServiceError> {
    if serial > Serial::MAX_STORED {
        return Err(ServiceError::invalid_zone_field(format!(
            "serial {} is beyond the stored range of {}",
            serial,
            Serial::MAX_STORED
        )));
    }
    if serial.as_u32() < 1 {
        return Err(ServiceError::invalid_zone_field(format!(
            "serial {} must be a positive integer",
            serial
        )));
    }

    if serial.as_u32() > MAX_INITIAL_SERIAL {
        return Err(ServiceError::invalid_zone_field(format!(
            "serial {} must not exceed {}, leaving room for the counter to advance",
            serial, MAX_INITIAL_SERIAL
        )));
    }

    Ok(serial)
}

#[cfg(test)]
mod tests {
    use bindizr_core::dns::Serial;

    use super::{
        MAX_INITIAL_SERIAL, generate_serial, validate_initial_serial, validate_stored_serial,
    };

    /// Verify that new zone serials start at one.
    #[test]
    fn a_new_zone_starts_at_one() {
        assert_eq!(generate_serial(None).unwrap(), Serial::from(1));
    }

    /// Verify that serials advance by exactly one.
    #[test]
    fn a_serial_advances_by_one() {
        assert_eq!(
            generate_serial(Some(Serial::from(1))).unwrap(),
            Serial::from(2)
        );
        assert_eq!(
            generate_serial(Some(Serial::from(41))).unwrap(),
            Serial::from(42)
        );
        assert_eq!(
            generate_serial(Some(Serial::from(2023010101))).unwrap(),
            Serial::from(2023010102)
        );
    }

    /// Verify that the stored ceiling refuses to advance rather than wrap.
    #[test]
    fn the_ceiling_is_an_error() {
        assert!(generate_serial(Some(Serial::MAX_STORED)).is_err());
    }

    /// Verify that the serial just below the ceiling still advances.
    #[test]
    fn the_step_before_the_ceiling_advances() {
        let below = Serial::from(Serial::MAX_STORED.as_u32() - 1);
        assert_eq!(generate_serial(Some(below)).unwrap(), Serial::MAX_STORED);
    }

    /// Verify that valid initial serials are accepted unchanged.
    #[test]
    fn valid_initial_serials_are_accepted() {
        for serial in [1, 2026072501, 1753401600, MAX_INITIAL_SERIAL] {
            assert_eq!(
                validate_initial_serial(Serial::from(serial)).unwrap(),
                Serial::from(serial)
            );
        }
    }

    /// Verify that a version serial is accepted up to the stored ceiling and
    /// refused as invalid input past it.
    #[test]
    fn serials_past_the_stored_range_are_invalid_input() {
        assert_eq!(
            validate_stored_serial(Serial::MAX_STORED).unwrap(),
            Serial::MAX_STORED
        );
        let err =
            validate_stored_serial(Serial::from(Serial::MAX_STORED.as_u32() + 1)).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::InvalidInput);
    }

    /// Verify that zero, a serial past the headroom, and one past the stored
    /// range are refused.
    #[test]
    fn out_of_range_initial_serials_are_refused() {
        assert!(validate_initial_serial(Serial::from(0)).is_err());
        assert!(validate_initial_serial(Serial::from(MAX_INITIAL_SERIAL + 1)).is_err());
        assert!(validate_initial_serial(Serial::from(Serial::MAX_STORED.as_u32() + 1)).is_err());
    }
}
