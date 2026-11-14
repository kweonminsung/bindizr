use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use chrono::Local;
use log::{Level, Log, Metadata, Record};
use serde_json::json;

use crate::config::{LogFormat, LogLevel, LoggingConfig};

/// The level in force, read per record so a config reload changes it without
/// replacing the installed logger — `log` allows only one.
static LOG_LEVEL: AtomicUsize = AtomicUsize::new(Level::Info as usize);

/// Whether lines are JSON objects, read per record for the same reason.
static LOG_JSON: AtomicBool = AtomicBool::new(false);

/// Read the currently configured logging threshold.
fn log_level() -> Level {
    Level::iter()
        .find(|level| *level as usize == LOG_LEVEL.load(Ordering::Relaxed))
        .unwrap_or(Level::Info)
}

/// Simple `log` implementation that writes to stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logger;

impl Log for Logger {
    /// Check whether a log record meets the current threshold.
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log_level()
    }

    /// Write an enabled log record to stderr with its timestamp.
    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // The offset keeps lines from replicas in other zones comparable.
        let at = Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z");
        let line = if LOG_JSON.load(Ordering::Relaxed) {
            // One object per line, the shape log pipelines split on.
            json!({
                "time": at.to_string(),
                "level": record.level().as_str(),
                "target": record.target(),
                "message": record.args().to_string()
            })
            .to_string()
        } else if log_level() >= Level::Debug {
            format!(
                "{at} {} - {}: {}",
                record.level(),
                record.target(),
                record.args()
            )
        } else {
            format!("{at} {}: {}", record.level(), record.args())
        };

        // Stderr keeps logs out of the CLI's stdout; a reader that stops
        // early must not panic the daemon.
        crate::errln!("{line}");
    }

    /// Flush buffered stderr output.
    fn flush(&self) {
        use std::io::Write;

        let _ = io::stderr().flush();
    }
}

impl From<LogLevel> for Level {
    /// Convert a configured logging level into the logging facade's level.
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => Self::Error,
            LogLevel::Warn => Self::Warn,
            LogLevel::Debug => Self::Debug,
            LogLevel::Trace => Self::Trace,
            LogLevel::Info => Self::Info,
        }
    }
}

impl Logger {
    /// Install the process-wide logger; reload changes its level and format
    /// through setters because the `log` facade permits only one installation.
    pub fn init(logging: &LoggingConfig) {
        let log_level = Level::from(logging.level);

        set_format(logging.format);

        if let Err(error) = log::set_boxed_logger(Box::new(Self)) {
            crate::errln!("Failed to set logger: {error}");
            return;
        }

        set_level(logging.level);

        log::info!("Console logging level: {log_level}");
    }
}

/// Change the level of the installed logger, for a configuration reload.
pub fn set_level(level: LogLevel) {
    let level = Level::from(level);
    LOG_LEVEL.store(level as usize, Ordering::Relaxed);
    log::set_max_level(level.to_level_filter());
}

/// Change the line shape of the installed logger, for a configuration reload.
pub fn set_format(format: LogFormat) {
    LOG_JSON.store(format == LogFormat::Json, Ordering::Relaxed);
}
