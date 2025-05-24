mod api;
mod config;
mod database;
mod rndc;
mod serializer;

use std::{env, fs, path::Path, process::exit};

#[cfg(unix)]
const PID_FILE: &str = "/tmp/bindizr.pid";
#[cfg(windows)]
const PID_FILE: &str = "bindizr.pid";

async fn bootstrap() {
    // Maintain initialization order
    config::initialize();
    database::initialize();
    serializer::initialize();
    api::initialize().await;
}

// Structure for command line argument processing
struct Args {
    command: String,
    foreground: bool,
    help: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = env::args().collect();

        if args.len() < 2 {
            return Err(format!("Usage: {} [start|stop] [OPTIONS]", args[0]));
        }

        let command = args[1].clone();
        let mut foreground = false;
        let mut help = false;

        if args.len() > 2 {
            match args[2].as_str() {
                "-f" | "--foreground" => foreground = true,
                "-h" | "--help" => help = true,
                _ => return Err(format!("Unsupported option: {}", args[2])),
            }
        }

        Ok(Args {
            command,
            foreground,
            help,
        })
    }

    fn help_message(program: &str) -> String {
        format!(
            "Usage: {} start [-f|--foreground] [-h|--help]\n\
            Options:\n\
            -f, --foreground   Run in foreground (default is background)\n\
            -h, --help         Show this help message",
            program
        )
    }
}

#[tokio::main]
async fn main() {
    #[cfg(not(any(windows, unix)))]
    {
        eprintln!("Unsupported platform. Only Windows and Unix-like systems are supported");
        exit(1);
    }

    // Parse command line arguments
    let args = match Args::parse() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{}", msg);
            exit(1);
        }
    };

    // Show help if requested
    if args.help {
        println!(
            "{}",
            Args::help_message(&env::args().next().unwrap_or_default())
        );
        exit(0);
    }

    // Execute command
    match args.command.as_str() {
        "start" => {
            if args.foreground {
                bootstrap().await;
            } else {
                platform::start();
            }
        }
        "stop" => platform::stop(),
        "bootstrap" => bootstrap().await,
        _ => {
            eprintln!("Unsupported command: {}", args.command);
            exit(1);
        }
    }
}

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

#[cfg(unix)]
mod platform {
    use super::*;
    use nix::sys::signal::{kill, SIGTERM};
    use nix::unistd::{fork, ForkResult, Pid};
    use std::{env, process::Command};

    pub fn start() {
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

    pub fn stop() {
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

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{env, process::Command};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    fn is_pid_running(pid: u32) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle == std::ptr::null_mut() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    pub fn start() {
        // Check PID file
        if let Some(pid_str) = read_pid_file() {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                if is_pid_running(pid) {
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

        let pid = child.id();
        if let Err(e) = write_pid_file(pid) {
            eprintln!("Failed to write PID file: {}", e);
            exit(1);
        }

        println!("Bindizr running with PID {}", pid);
    }

    pub fn stop() {
        // Check PID file
        let pid_str = match read_pid_file() {
            Some(pid) => pid,
            None => {
                println!("Bindizr not running");
                return;
            }
        };

        // Parse PID
        let pid = match pid_str.trim().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => {
                let _ = remove_pid_file();
                println!("Invalid PID in file, removed stale PID file");
                return;
            }
        };

        // Terminate process
        if is_pid_running(pid) {
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
