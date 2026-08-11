//! Wall-clock helpers for the per-stage debug timing summaries.

use std::time::{Duration, Instant};

/// Milliseconds in `duration`, fractional.
pub(crate) fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// Milliseconds elapsed since `start`, fractional.
pub(crate) fn elapsed_ms(start: Instant) -> f64 {
    duration_ms(start.elapsed())
}
