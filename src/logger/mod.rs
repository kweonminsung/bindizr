use crate::config;
use chrono::Local;
use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::sync::Mutex;

pub struct Logger {
    file: Option<Mutex<File>>,
    level: Level,
    enable_file_logging: bool,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let log_message = format!(
                "[{}] {} - {}: {}\n",
                now,
                record.level(),
                record.target(),
                record.args()
            );

            // 항상 콘솔에 출력
            print!("{}", log_message);

            // enable_file_logging이 true이고 파일이 설정된 경우에만 파일에 기록
            if self.enable_file_logging {
                if let Some(file) = &self.file {
                    if let Ok(mut file) = file.lock() {
                        let _ = file.write_all(log_message.as_bytes());
                    }
                }
            }
        }
    }

    fn flush(&self) {
        // 콘솔 출력 flush
        let _ = io::stdout().flush();

        // 파일 출력 flush (필요한 경우)
        if self.enable_file_logging {
            if let Some(file) = &self.file {
                if let Ok(mut file) = file.lock() {
                    let _ = file.flush();
                }
            }
        }
    }
}

use std::env;
use std::path::Path as StdPath;

pub fn initialize() -> Result<(), SetLoggerError> {
    let enable_logging = config::get_config("log.enable_logging")
        .parse::<bool>()
        .unwrap_or(false);

    let log_level = match config::get_config("log.log_level").to_lowercase().as_str() {
        "error" => Level::Error,
        "warn" => Level::Warn,
        "debug" => Level::Debug,
        "trace" => Level::Trace,
        _ => Level::Info,
    };

    let log_file_path = if enable_logging {
        let path = config::get_config("log.log_file_path");

        // 빈 문자열이면 현재 디렉토리에 기본 로그 파일 사용
        let path = if path.trim().is_empty() {
            match env::current_dir() {
                Ok(current_dir) => current_dir
                    .join("bindizr.log")
                    .to_string_lossy()
                    .to_string(),
                Err(_) => "bindizr.log".to_string(), // 현재 디렉토리를 가져올 수 없는 경우 기본값
            }
        } else {
            path
        };

        // 경로의 디렉토리 부분이 존재하는지 확인
        if let Some(parent) = StdPath::new(&path).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                // 디렉토리가 존재하지 않으면 생성 시도
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("Failed to create log directory {}: {}", parent.display(), e);
                    // 디렉토리 생성 실패 시 현재 디렉토리 사용
                    return initialize_with_path(
                        enable_logging,
                        log_level,
                        "bindizr.log".to_string(),
                    );
                }
            }
        }

        Some(path)
    } else {
        None
    };

    initialize_with_path(enable_logging, log_level, log_file_path.unwrap_or_default())
}

// 로그 초기화 로직을 별도 함수로 분리
fn initialize_with_path(
    enable_logging: bool,
    log_level: Level,
    log_file_path: String,
) -> Result<(), SetLoggerError> {
    // 파일 로깅이 활성화된 경우 파일 열기
    let file = if enable_logging {
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)
        {
            Ok(file) => {
                println!("Logging to file: {}", log_file_path);
                Some(Mutex::new(file))
            }
            Err(e) => {
                eprintln!("Failed to open log file {}: {}", log_file_path, e);
                None
            }
        }
    } else {
        None
    };

    // 로거 생성
    let logger = Logger {
        file,
        level: log_level,
        enable_file_logging: enable_logging,
    };

    // 로거 설정
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(LevelFilter::from(log_level));

    // 로깅 시작 메시지
    if enable_logging {
        log_info!(
            "Logging initialized. Level: {}, File: {}",
            log_level,
            log_file_path
        );
    } else {
        log_info!(
            "File logging disabled. Console logging level: {}",
            log_level
        );
    }

    Ok(())
}

// 로그 매크로 정의
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
