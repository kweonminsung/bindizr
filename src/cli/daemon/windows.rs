use super::DaemonControl;
use crate::cli::daemon::{get_pid, remove_pid_file, write_pid_file};
use std::{
    env,
    process::{exit, Command},
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::{
    Foundation::{CloseHandle, STILL_ACTIVE},
    System::Threading::GetExitCodeProcess,
};

pub struct WindowsDaemon;

impl DaemonControl for WindowsDaemon {
    fn is_pid_running(pid: i32) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
            if handle.is_null() {
                return false;
            }

            let mut exit_code = 0;
            let success = GetExitCodeProcess(handle, &mut exit_code);
            CloseHandle(handle);

            success != 0 && exit_code == STILL_ACTIVE as u32
        }
    }

    fn start() {
        // Check if daemon is already running
        if let Some(pid) = get_pid() {
            if Self::is_pid_running(pid) {
                println!("Bindizr is already running with PID {}", pid);
                return;
            } else {
                let _ = remove_pid_file();
            }
        }

        // Create daemon process
        let exe = env::current_exe().expect("Failed to get executable path");

        #[allow(clippy::zombie_processes)]
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
        let pid = match get_pid() {
            Some(pid) => pid,
            None => {
                println!("Bindizr not running");
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
