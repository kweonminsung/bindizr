use super::DaemonControl;
use crate::cli::daemon::{get_pid, remove_pid_file, write_pid_file};
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
        // Check if daemon is already running
        if let Some(pid) = get_pid() {
            if Self::is_pid_running(pid) {
                println!("Bindizr is already running with PID {}", pid);
                return;
            } else {
                // Remove stale PID file
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
        let pid = match get_pid() {
            Some(pid) => pid,
            None => {
                println!("Bindizr not running");
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
