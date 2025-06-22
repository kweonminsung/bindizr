mod pid;
mod unix;

use pid::PID_FILE_PATH;
use std::{fs, path::Path};
use unix::UnixProcess as Process;

// Daemon control trait
trait ProcessCtl {
    fn start();
    fn _stop();
    fn is_pid_running(pid: i32) -> bool;
}

pub fn start() {
    Process::start();
}

// Check if the daemon is running
// pub fn is_running() -> bool {
//     match get_pid() {
//         Some(pid) => Process::is_pid_running(pid),
//         None => false,
//     }
// }

pub fn get_pid() -> Option<i32> {
    if Path::new(PID_FILE_PATH).exists() {
        if let Ok(pid_str) = fs::read_to_string(PID_FILE_PATH) {
            return pid_str.trim().parse::<i32>().ok();
        }
    }
    None
}

pub fn remove_pid_file() -> Result<(), String> {
    if Path::new(PID_FILE_PATH).exists() {
        fs::remove_file(PID_FILE_PATH).map_err(|e| format!("Failed to remove PID file: {}", e))
    } else {
        Ok(())
    }
}

pub fn write_pid_file(pid: u32) -> Result<(), String> {
    fs::write(PID_FILE_PATH, pid.to_string())
        .map_err(|e| format!("Failed to write PID file: {}", e))
}
