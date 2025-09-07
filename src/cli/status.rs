use crate::{
    daemon::socket::{client::DaemonSocketClient, dto::DaemonStatusResponse},
    log_debug,
};

pub async fn handle_command() -> Result<(), String> {
    let client = DaemonSocketClient::new();

    // Create socket request
    let res = client.send_command("status", None).await?;

    log_debug!("Status command result: {:?}", res);

    let status: DaemonStatusResponse = serde_json::from_value(res.data)
        .map_err(|e| format!("Failed to parse status response: {}", e))?;

    println!("=== BINDIZR STATUS ===");

    println!("Status: \x1b[32mRunning\x1b[0m");

    let pid = match status.pid {
        Some(pid) => pid.to_string(),
        None => "Unknown".to_string(),
    };
    println!("PID: {}", pid);

    println!("Version: {}", status.version);

    println!("Loaded Configurations:");
    if let serde_json::Value::Object(sections) = status.config_map {
        for (section, value) in sections {
            println!("\x1b[36m[{}]\x1b[0m", section);

            match value {
                serde_json::Value::Object(table) => {
                    for (k, v) in table {
                        println!("  \x1b[33m{:<22}\x1b[0m = {}", k, v);
                    }
                }
                other => {
                    println!("  \x1b[33m<value>\x1b[0m = {}", other);
                }
            }

            println!();
        }
    } else {
        println!("\n\x1b[31mFailed to collect configuration\x1b[0m");
    }
    Ok(())
}
