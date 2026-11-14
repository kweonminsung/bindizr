//! Elapsed time for the per-stage timing summaries.

use std::time::Instant;

/// Milliseconds elapsed since `started`, fractional.
pub(crate) fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}
