use std::{
    io::{self, Write},
    sync::atomic::{AtomicUsize, Ordering},
};

use chrono::Local;
use log::{Level, Metadata, Record};

use crate::config;

/// The level in force, read per record so a config reload changes it without
/// replacing the installed logger — `log` allows only one.
static LOG_LEVEL: AtomicUsize = AtomicUsize::new(Level::Info as usize);

/// Read the currently configured logging threshold.
fn log_level() -> Level {
    Level::iter()
        .find(|level| *level as usize == LOG_LEVEL.load(Ordering::Relaxed))
        .unwrap_or(Level::Info)
}

/// Simple `log` implementation that writes to stderr.
struct Logger;

impl log::Log for Logger {
    /// Check whether a log record meets the current threshold.
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log_level()
    }

    /// Write an enabled log record to stderr with its timestamp.
    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            // The offset keeps lines from replicas in other zones comparable.
            let at = Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z");
            let log_message = if log_level() >= Level::Debug {
                format!(
                    "{} {} - {}: {}\n",
                    at,
                    record.level(),
                    record.target(),
                    record.args()
                )
            } else {
                format!("{} {}: {}\n", at, record.level(), record.args())
            };

            // Use stderr for logging to avoid interfering with stdout
            eprint!("{}", log_message);
        }
    }

    /// Flush buffered stderr output.
    fn flush(&self) {
        let _ = io::stderr().flush();
    }
}

impl From<config::LogLevel> for Level {
    /// Convert a configured logging level into the logging facade's level.
    fn from(level: config::LogLevel) -> Self {
        match level {
            config::LogLevel::Error => Level::Error,
            config::LogLevel::Warn => Level::Warn,
            config::LogLevel::Debug => Level::Debug,
            config::LogLevel::Trace => Level::Trace,
            config::LogLevel::Info => Level::Info,
        }
    }
}

/// Install the global logger using the configured log level.
pub fn initialize() {
    initialize_with_level(config::bindizr_config().logging.log_level);
}

/// Install the global logger at an explicit level, for binaries that do not
/// load the bindizr configuration file (e.g. the ExternalDNS adapter).
pub fn initialize_with_level(level: config::LogLevel) {
    let log_level = Level::from(level);

    if let Err(e) = log::set_boxed_logger(Box::new(Logger)) {
        eprintln!("Failed to set logger: {}", e);
        return;
    }
    set_level(level);

    log::info!("Console logging level: {}", log_level);
}

/// Change the level of the installed logger, for a configuration reload.
pub fn set_level(level: config::LogLevel) {
    let level = Level::from(level);
    LOG_LEVEL.store(level as usize, Ordering::Relaxed);
    log::set_max_level(level.to_level_filter());
}
