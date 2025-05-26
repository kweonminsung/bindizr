use std::{fs, path::Path, process::exit};

#[cfg(unix)]
const PID_FILE: &str = "/tmp/bindizr.pid";
#[cfg(windows)]
const PID_FILE: &str = "bindizr.pid";

// Common functions for PID file management
fn read_pid_file() -> Option<String> {
    if Path::new(PID_FILE).exists() {
        fs::read_to_string(PID_FILE).ok()
    } else {
        None
    }
}

fn remove_pid_file() -> Result<(), std::io::Error> {
    if Path::new(PID_FILE).exists() {
        fs::remove_file(PID_FILE)
    } else {
        Ok(())
    }
}

fn write_pid_file(pid: u32) -> Result<(), std::io::Error> {
    fs::write(PID_FILE, pid.to_string())
}
