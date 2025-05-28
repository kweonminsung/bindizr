use std::{fs, path::Path};

#[cfg(unix)]
pub(crate) const PID_FILE: &str = "/tmp/bindizr.pid";
#[cfg(windows)]
pub(crate) const PID_FILE: &str = "bindizr.pid";

pub(crate) trait DaemonControl {
    fn start();
    fn stop();
    fn is_pid_running(pid: i32) -> bool;
}

// Check if the daemon is running
pub(crate) fn is_running() -> bool {
    match read_pid_file() {
        Some(pid_str) => {
            #[cfg(unix)]
            {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    return Daemon::is_pid_running(pid);
                }
            }
            #[cfg(windows)]
            {
                if let Ok(pid) = pid_str.trim().parse::<i32>() {
                    return Daemon::is_pid_running(pid);
                }
            }
            false
        }
        None => false,
    }
}

// Common functions for PID file management
pub(crate) fn read_pid_file() -> Option<String> {
    if Path::new(PID_FILE).exists() {
        fs::read_to_string(PID_FILE).ok()
    } else {
        None
    }
}

pub(crate) fn remove_pid_file() -> Result<(), std::io::Error> {
    if Path::new(PID_FILE).exists() {
        fs::remove_file(PID_FILE)
    } else {
        Ok(())
    }
}

pub(crate) fn write_pid_file(pid: u32) -> Result<(), std::io::Error> {
    fs::write(PID_FILE, pid.to_string())
}

// Import platform-specific implementations
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

// Export the appropriate implementation
#[cfg(unix)]
pub(crate) use unix::UnixDaemon as Daemon;
#[cfg(windows)]
pub(crate) use windows::WindowsDaemon as Daemon;
