use std::{fs, path::Path};

// PID file path according to the platform
#[cfg(unix)]
pub const PID_FILE: &str = "/tmp/bindizr.pid";
#[cfg(windows)]
pub const PID_FILE: &str = "bindizr.pid";

// Import platform-specific implementations
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

// Daemon according to the platform
#[cfg(unix)]
use unix::UnixDaemon as Daemon;
#[cfg(windows)]
use windows::WindowsDaemon as Daemon;

// Daemon control trait
trait DaemonControl {
    fn start();
    fn stop();
    fn is_pid_running(pid: i32) -> bool;
}

pub fn start() {
    Daemon::start();
}

pub fn stop() {
    Daemon::stop();
}

// Check if the daemon is running
pub fn is_running() -> bool {
    match get_pid() {
        Some(pid) => Daemon::is_pid_running(pid),
        None => false,
    }
}

pub fn get_pid() -> Option<i32> {
    if Path::new(PID_FILE).exists() {
        if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
            return pid_str.trim().parse::<i32>().ok();
        }
    }
    None
}

pub fn remove_pid_file() -> Result<(), std::io::Error> {
    if Path::new(PID_FILE).exists() {
        fs::remove_file(PID_FILE)
    } else {
        Ok(())
    }
}

pub fn write_pid_file(pid: u32) -> Result<(), std::io::Error> {
    fs::write(PID_FILE, pid.to_string())
}
