mod api;
mod config;
mod database;
mod rndc;
mod serializer;

use std::env;

async fn bootstrap() {
    // load config
    config::initialize();

    // initialize database connection pool
    database::initialize();

    // initialize serializer thread
    serializer::initialize();

    // initialize API server
    api::initialize().await;
}

#[tokio::main]
async fn main() {
    #[cfg(not(any(windows, unix)))]
    {
        eprintln!("Unsupported platform. Only Windows and Unix-like systems are supported");
        std::process::exit(1);
    }

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [start|stop|-f|--foreground]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "start" => platform::start(),
        "stop" => platform::stop(),
        "-f" | "--foreground" => bootstrap().await,
        _ => eprintln!("Unsupported command"),
    }
}

#[cfg(unix)]
mod platform {
    use nix::sys::signal::{kill, SIGTERM};
    use nix::unistd::{fork, ForkResult, Pid};
    use std::{
        env, fs,
        path::Path,
        process::{exit, Command},
    };

    const PID_FILE: &str = "/tmp/bindizr.pid";

    pub fn start() {
        if Path::new(PID_FILE).exists() {
            let pid_str = fs::read_to_string(PID_FILE).unwrap_or_default();
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                let result = kill(Pid::from_raw(pid), None);
                match result {
                    Ok(_) => {
                        println!("Bindizr is already running with PID {}", pid);
                        return;
                    }
                    Err(nix::errno::Errno::ESRCH) => {
                        // remove stale PID file
                        let _ = fs::remove_file(PID_FILE);
                    }
                    // fail to check if process is running
                    Err(_) => {
                        return;
                    }
                }
            } else {
                // remove invalid PID file
                let _ = fs::remove_file(PID_FILE);
            }
        }

        match unsafe { fork() } {
            Ok(ForkResult::Parent { .. }) => {
                // parent process does nothing, just exits
                exit(0);
            }
            Ok(ForkResult::Child) => {
                // rerun with --foreground flag
                let exe = env::current_exe().unwrap();
                let child = Command::new(exe)
                    .arg("--foreground")
                    .spawn()
                    .expect("Failed to start");

                let pid = child.id();
                fs::write(PID_FILE, pid.to_string()).unwrap();
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
        if !Path::new(PID_FILE).exists() {
            println!("Bindizr not running");
            return;
        }

        let pid_str = fs::read_to_string(PID_FILE).unwrap_or_default();
        let pid = match pid_str.trim().parse::<i32>() {
            Ok(pid) => pid,
            Err(_) => {
                // remove invalid PID file
                let _ = fs::remove_file(PID_FILE);
                return;
            }
        };

        match kill(Pid::from_raw(pid), SIGTERM) {
            Ok(_) => {
                println!("Stopped bindizr (PID {})", pid);
                let _ = fs::remove_file(PID_FILE);
            }
            Err(nix::errno::Errno::ESRCH) => {
                // process not found, remove the PID file
                let _ = fs::remove_file(PID_FILE);
            }
            Err(e) => {
                // etc errors(permission denied, etc)
                eprintln!("Failed to kill process: {}", e);
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::{env, fs, path::Path, process::Command};

    const PID_FILE: &str = "bindizr.pid";

    fn is_pid_running(pid: u32) -> bool {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);

            // no process or access denied
            if handle == std::ptr::null_mut() {
                return false;
            }
            CloseHandle(handle);
            true
        }
    }

    pub fn start() {
        if Path::new(PID_FILE).exists() {
            let pid_str = fs::read_to_string(PID_FILE).unwrap_or_default();
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                if is_pid_running(pid) {
                    println!("Bindizr is already running with PID {}", pid);
                    return;
                } else {
                    // remove stale PID file
                    let _ = fs::remove_file(PID_FILE);
                }
            } else {
                // remove invalid PID file
                let _ = fs::remove_file(PID_FILE);
            }
        }

        let exe = env::current_exe().unwrap();
        let child = Command::new(exe)
            .arg("--foreground")
            .spawn()
            .expect("Failed to start");

        let pid = child.id();
        fs::write(PID_FILE, pid.to_string()).unwrap();
        println!("Bindizr running with PID {}", pid);
    }

    pub fn stop() {
        if !Path::new(PID_FILE).exists() {
            println!("Bindizr not running");
            return;
        }

        let pid_str = fs::read_to_string(PID_FILE).unwrap_or_default();
        let pid = match pid_str.trim().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => {
                // remove invalid PID file
                let _ = fs::remove_file(PID_FILE);
                return;
            }
        };

        if is_pid_running(pid) {
            let status = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .status()
                .unwrap();

            if status.success() {
                println!("Stopped bindizr (PID {})", pid);
                let _ = fs::remove_file(PID_FILE);
            } else {
                eprintln!("Failed to kill process");
            }
        } else {
            // remove stale PID file
            let _ = fs::remove_file(PID_FILE);
        }
    }
}
