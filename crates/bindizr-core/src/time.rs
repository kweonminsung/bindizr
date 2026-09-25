//! Clock readings: wall-clock stamps for the metrics and the daemon status,
//! and elapsed time for the per-stage timing summaries.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch, 0 for a clock set before it.
pub fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Milliseconds elapsed since `start`, fractional.
pub fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
