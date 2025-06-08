use super::DaemonControl;
use crate::cli::daemon::{read_pid_file, remove_pid_file, write_pid_file};
use std::{
    env,
    process::{exit, Command},
};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

pub(crate) struct WindowsDaemon;

impl DaemonControl for WindowsDaemon {
    fn is_pid_running(pid: i32) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
            if handle.is_null() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    fn start() {
        // Check PID file
        if let Some(pid_str) = read_pid_file() {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if Self::is_pid_running(pid) {
                    println!("Bindizr is already running with PID {}", pid);
                    return;
                } else {
                    let _ = remove_pid_file();
                }
            } else {
                let _ = remove_pid_file();
            }
        }

        // Start new process
        let exe = env::current_exe().expect("Failed to get executable path");
        let child = Command::new(exe)
            .arg("bootstrap")
            .spawn()
            .expect("Failed to start process");

        let pid = child.id() as i32;
        if let Err(e) = write_pid_file(pid as u32) {
            eprintln!("Failed to write PID file: {}", e);
            exit(1);
        }

        println!("Bindizr running with PID {}", pid);
    }

    fn stop() {
        // Check PID file
        let pid_str = match read_pid_file() {
            Some(pid) => pid,
            None => {
                println!("Bindizr not running");
                return;
            }
        };

        // Parse PID
        let pid = match pid_str.trim().parse::<i32>() {
            Ok(pid) => pid,
            Err(_) => {
                let _ = remove_pid_file();
                println!("Invalid PID in file, removed stale PID file");
                return;
            }
        };

        // Terminate process
        if Self::is_pid_running(pid) {
            let status = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .status()
                .expect("Failed to execute taskkill");

            if status.success() {
                println!("Stopped bindizr (PID {})", pid);
                let _ = remove_pid_file();
            } else {
                eprintln!("Failed to kill process");
            }
        } else {
            println!("Process not found, removed stale PID file");
            let _ = remove_pid_file();
        }
    }
}
