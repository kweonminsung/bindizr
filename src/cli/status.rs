use crate::{cli::daemon, config};

pub fn help_message() -> String {
    "Usage: bindizr status\n\
    \n\
    Show the current status of the bindizr service\n\
    \n\
    Options:\n\
    -h, --help         Show this help message"
        .to_string()
}

pub fn handle_command() -> Result<(), String> {
    println!("=== BINDIZR STATUS ===");

    // Check if daemon is running
    if daemon::is_running() {
        let pid = match daemon::get_pid() {
            Some(pid) => pid.to_string(),
            None => "Unknown".to_string(),
        };

        println!("Status: \x1b[32mRunning\x1b[0m");
        println!("PID: {}", pid);

        let version = env!("CARGO_PKG_VERSION");
        println!("Version: {}", version);

        println!("\nLoaded Configurations:");
        let config_map = config::get_config_map();
        if let Ok(sections) = config_map {
            for (section, value) in sections {
                println!("\n\x1b[36m[{}]\x1b[0m", section);

                if let Ok(table) = value.into_table() {
                    for (k, v) in table {
                        println!("  \x1b[33m{:<22}\x1b[0m = {}", k, v);
                    }
                } else {
                    println!("  (not a table)");
                }
            }
        } else {
            println!("\n\x1b[31mFailed to collect configuration\x1b[0m");
        }
    } else {
        println!("Status: \x1b[31mNot running\x1b[0m");
    }

    Ok(())
}
