use super::DaemonControl;
use crate::cli::daemon::{read_pid_file, remove_pid_file, write_pid_file};
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::{fork, ForkResult, Pid};
use std::{
    env,
    process::{exit, Command},
};

pub struct UnixDaemon;

impl DaemonControl for UnixDaemon {
    fn is_pid_running(pid: i32) -> bool {
        match kill(Pid::from_raw(pid), None) {
            Ok(_) => true,
            Err(nix::errno::Errno::ESRCH) => false,
            Err(_) => {
                // Assuming any other error means the process is running
                true
            }
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
                    // Remove stale PID file
                    let _ = remove_pid_file();
                }
            } else {
                // Remove invalid PID file
                let _ = remove_pid_file();
            }
        }

        // Create daemon process
        match unsafe { fork() } {
            Ok(ForkResult::Parent { .. }) => exit(0),
            Ok(ForkResult::Child) => {
                // Re-execute with bootstrap command
                let exe = env::current_exe().expect("Failed to get executable path");
                let child = Command::new(exe)
                    .arg("bootstrap")
                    .spawn()
                    .expect("Failed to start process");

                let pid = child.id();
                if let Err(e) = write_pid_file(pid) {
                    eprintln!("Failed to write PID file: {}", e);
                    exit(1);
                }

                println!("Bindizr running with PID {}", pid);
                exit(0);
            }
            Err(e) => {
                eprintln!("Fork failed: {}", e);
                exit(1);
            }
        }
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
            match kill(Pid::from_raw(pid), SIGTERM) {
                Ok(_) => {
                    println!("Stopped bindizr (PID {})", pid);
                    let _ = remove_pid_file();
                }
                Err(e) => {
                    eprintln!("Failed to kill process: {}", e);
                }
            }
        } else {
            println!("Process not found, removed stale PID file");
            let _ = remove_pid_file();
        }
    }
}
