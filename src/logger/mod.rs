use crate::config;
use log::{Level, Metadata, Record};
use std::io::{self, Write};

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        log::warn!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        log::info!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        log::trace!($($arg)*)
    };
}

pub struct Logger {
    log_level: Level,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let log_message = if self.log_level == Level::Debug {
                // Include target in debug logs
                format!(
                    "{} - {}: {}\n",
                    record.level(),
                    record.target(),
                    record.args()
                )
            } else {
                // Exclude target for other log levels
                format!("{}: {}\n", record.level(), record.args())
            };

            print!("{}", log_message);
        }
    }

    fn flush(&self) {
        let _ = io::stdout().flush();
    }
}

pub fn initialize() {
    let log_level = match config::get_config::<String>("logging.log_level")
        .to_lowercase()
        .as_str()
    {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "debug" => Level::Debug,
        "trace" => Level::Trace,
        _ => Level::Info,
    };

    let logger = Logger { log_level };

    if let Err(e) = log::set_boxed_logger(Box::new(logger)) {
        eprintln!("Failed to set logger: {}", e);
        return;
    }
    log::set_max_level(log_level.to_level_filter());

    println!("Console logging level: {}", log_level);
}
