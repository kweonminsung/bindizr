mod api;
mod config;
mod database;
mod rndc;
mod serializer;

use std::env;

pub async fn bootstrap() {
    // load config
    config::initialize();

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
    use std::{fs, path::Path, process::exit};

    const PID_FILE: &str = "/tmp/bindizr.pid";

    pub fn start() {
        if Path::new(PID_FILE).exists() {
            println!("Bindizr is already running");
            return;
        }

        match unsafe { fork() } {
            Ok(ForkResult::Parent { .. }) => {
                // parent process does nothing, just exits
                return;
            }
            Ok(ForkResult::Child) => {
                let pid = std::process::id();
                fs::write(PID_FILE, pid.to_string()).unwrap();
                println!("Bindizr running with PID {}", pid);

                // rerun with --foreground flag
                let exe = std::env::current_exe().unwrap();
                let err = std::process::Command::new(exe)
                    .arg("--foreground")
                    .spawn()
                    .expect("Failed to start");

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

        let pid = fs::read_to_string(PID_FILE)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();

        if kill(Pid::from_raw(pid), SIGTERM).is_ok() {
            println!("Stopped bindizr (pid {})", pid);
            fs::remove_file(PID_FILE).unwrap_or_default();
        } else {
            eprintln!("Failed to kill process");
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::{env, fs, path::Path, process::Command};

    const PID_FILE: &str = "bindizr.pid";

    pub fn start() {
        if Path::new(PID_FILE).exists() {
            println!("Bindizr already running");
            return;
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

        let pid = fs::read_to_string(PID_FILE)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();

        let status = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
            .unwrap();

        if status.success() {
            println!("Stopped bindizr (pid {})", pid);
            fs::remove_file(PID_FILE).unwrap_or_default();
        } else {
            eprintln!("Failed to kill process");
        }
    }
}
