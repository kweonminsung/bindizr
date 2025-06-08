use crate::cli::daemon;
use crate::config;
use chrono::Local;
use log::{Level, Metadata, Record};
use std::env;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        log::warn!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        log::info!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        log::trace!($($arg)*);
    };
}

pub(crate) struct Logger {
    log_level: Level,
    enable_file_logging: bool,
    log_dir_path: Option<PathBuf>,
    is_daemon: bool,
    current_file: Arc<Mutex<Option<File>>>,
    current_date: Arc<Mutex<String>>,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = Local::now();
            let formatted_time = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let today = now.format("%Y-%m-%d").to_string();

            let log_message = if self.log_level == Level::Debug {
                // Include target in debug logs
                format!(
                    "[{}] {} - {}: {}\n",
                    formatted_time,
                    record.level(),
                    record.target(),
                    record.args()
                )
            } else {
                // Exclude target for other log levels
                format!(
                    "[{}] {}: {}\n",
                    formatted_time,
                    record.level(),
                    record.args()
                )
            };

            // Print to console only in foreground mode
            if !self.is_daemon {
                print!("{}", log_message);
            }

            // Save to file if logging is enabled
            if self.enable_file_logging {
                if let Some(log_dir) = &self.log_dir_path {
                    // Check if date has changed and rotate log file if needed
                    let mut current_date = self.current_date.lock().unwrap();
                    if *current_date != today {
                        *current_date = today.clone();
                        // Create new log file for the new day
                        let mut current_file = self.current_file.lock().unwrap();
                        *current_file = self.open_log_file(log_dir, &today);
                    }

                    // Write to the current log file
                    if let Ok(mut file_guard) = self.current_file.lock() {
                        if let Some(file) = &mut *file_guard {
                            let _ = file.write_all(log_message.as_bytes());
                        }
                    }
                }
            }
        }
    }

    fn flush(&self) {
        // Flush console output
        let _ = io::stdout().flush();

        // Flush file output if needed
        if self.enable_file_logging {
            if let Ok(mut file_guard) = self.current_file.lock() {
                if let Some(file) = &mut *file_guard {
                    let _ = file.flush();
                }
            }
        }
    }
}

impl Logger {
    fn open_log_file(&self, log_dir: &Path, date: &str) -> Option<File> {
        let file_name = format!("bindizr_{}.log", date);
        let file_path = log_dir.join(file_name);

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
        {
            Ok(file) => {
                println!("Logging to file: {}", file_path.display());
                Some(file)
            }
            Err(e) => {
                eprintln!("Failed to open log file {}: {}", file_path.display(), e);
                None
            }
        }
    }
}

pub(crate) fn initialize() {
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

    let enable_file_logging = config::get_config::<bool>("logging.enable_file_logging");

    if !enable_file_logging {
        return initialize_with_dir(enable_file_logging, log_level, None);
    }

    // Get log directory
    let log_dir = config::get_config::<String>("logging.log_output_dir");
    let log_dir_path = if !log_dir.is_empty() {
        PathBuf::from(&log_dir)
    } else {
        env::current_dir().unwrap()
    };

    // Create log directory if it doesn't exist
    if !log_dir_path.exists() {
        if let Err(e) = create_dir_all(&log_dir_path) {
            eprintln!(
                "Failed to create log directory {}: {}",
                log_dir_path.display(),
                e
            );
            return initialize_with_dir(enable_file_logging, log_level, None);
        }
    }

    initialize_with_dir(enable_file_logging, log_level, Some(log_dir_path));
}

// Initialize logger with specified directory
fn initialize_with_dir(enable_file_logging: bool, log_level: Level, log_dir_path: Option<PathBuf>) {
    let today = Local::now().format("%Y-%m-%d").to_string();

    // Create initial log file if logging is enabled
    let (current_file, file_path) = if enable_file_logging && log_dir_path.is_some() {
        let dir = log_dir_path.as_ref().unwrap();
        let file_name = format!("bindizr_{}.log", today);
        let file_path = dir.join(&file_name);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path);

        match file {
            Ok(file) => (Some(file), Some(file_path)),
            Err(e) => {
                eprintln!("Failed to open log file {}: {}", file_path.display(), e);
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    // Create logger
    let logger = Logger {
        log_level: log_level,
        enable_file_logging,
        log_dir_path,
        is_daemon: daemon::is_running(),
        current_file: Arc::new(Mutex::new(current_file)),
        current_date: Arc::new(Mutex::new(today)),
    };

    // Set up logger
    if let Err(e) = log::set_boxed_logger(Box::new(logger)) {
        eprintln!("Failed to set logger: {}", e);
        return;
    }
    log::set_max_level(log_level.to_level_filter());

    // Log initialization message
    if enable_file_logging {
        if let Some(path) = file_path {
            // Get absolute path for logging
            let absolute_path = path
                .canonicalize()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.display().to_string());

            println!(
                "Logging initialized. Level: {}, File: {}",
                log_level, absolute_path
            );
        } else {
            println!("Logging initialized. Level: {}", log_level);
        }
    } else {
        println!(
            "File logging disabled. Console logging level: {}",
            log_level
        );
    }
}
