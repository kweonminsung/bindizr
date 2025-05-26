use super::{DaemonControl, read_pid_file, remove_pid_file, write_pid_file};
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::{fork, ForkResult, Pid};
use std::{env, process::{Command, exit}};

pub struct UnixDaemon;

impl DaemonControl for UnixDaemon {
    use super::*;
    use nix::sys::signal::{kill, SIGTERM};
    use nix::unistd::{fork, ForkResult, Pid};
    use std::{env, process::Command};

    fn start() {
        // Check PID file
        if let Some(pid_str) = read_pid_file() {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                match kill(Pid::from_raw(pid), None) {
                    Ok(_) => {
                        println!("Bindizr is already running with PID {}", pid);
                        return;
                    }
                    Err(nix::errno::Errno::ESRCH) => {
                        // Remove stale PID file
                        let _ = remove_pid_file();
                    }
                    Err(e) => {
                        eprintln!("Error checking process: {}", e);
                        return;
                    }
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
        match kill(Pid::from_raw(pid), SIGTERM) {
            Ok(_) => {
                println!("Stopped bindizr (PID {})", pid);
                let _ = remove_pid_file();
            }
            Err(nix::errno::Errno::ESRCH) => {
                println!("Process not found, removed stale PID file");
                let _ = remove_pid_file();
            }
            Err(e) => {
                eprintln!("Failed to kill process: {}", e);
            }
        }
    }
}