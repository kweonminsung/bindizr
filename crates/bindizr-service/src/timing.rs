//! Wall-clock helper for the per-stage debug timing summaries.

use std::time::Instant;

/// Milliseconds elapsed since `start`, fractional.
pub(crate) fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
