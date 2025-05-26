use std::{fs, path::Path};

#[cfg(unix)]
pub const PID_FILE: &str = "/tmp/bindizr.pid";
#[cfg(windows)]
pub const PID_FILE: &str = "bindizr.pid";

pub trait DaemonControl {
    fn start();
    fn stop();
    fn is_pid_running(pid: u32) -> bool;
}

// Common functions for PID file management
pub fn read_pid_file() -> Option<String> {
    if Path::new(PID_FILE).exists() {
        fs::read_to_string(PID_FILE).ok()
    } else {
        None
    }
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

// Import platform-specific implementations
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

// Export the appropriate implementation
#[cfg(unix)]
pub use unix::UnixDaemon as Daemon;
#[cfg(windows)]
pub use windows::WindowsDaemon as Daemon;
