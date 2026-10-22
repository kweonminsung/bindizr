//! Serial generation uses the complete DNS serial space, wrapping past the
//! maximum to one, never zero (RFC 2136, Section 7.11).

use bindizr_core::dns::Serial;

/// Start at one or advance modulo 2^32 (RFC 1982, Section 3.1), skipping zero.
pub(crate) fn generate_serial(current_serial: Option<Serial>) -> Serial {
    current_serial.map_or(Serial::from(1), Serial::next)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generation advances across both signed and unsigned integer boundaries.
    #[test]
    fn serials_advance_through_the_entire_wire_range() {
        assert_eq!(generate_serial(None), Serial::from(1));

        for (before, after) in [(1, 2), (0x7fff_ffff, 0x8000_0000), (u32::MAX, 1)] {
            assert_eq!(
                generate_serial(Some(Serial::from(before))),
                Serial::from(after)
            );
        }
    }
}
