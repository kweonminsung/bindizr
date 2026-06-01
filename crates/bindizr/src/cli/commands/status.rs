use crate::{
    log_debug,
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, DaemonStatusResponse},
    },
};

pub(crate) async fn handle_command() -> Result<(), String> {
    let client = DaemonSocketClient::new();

    // Create socket request
    let res = client.send_command(DaemonCommandKind::Status, None).await?;

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
    println!("\x1b[36m[root]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "listen_addr", status.config.listen_addr
    );
    println!();

    println!("\x1b[36m[api]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "listen_port", status.config.api.listen_port
    );
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "require_authentication", status.config.api.require_authentication
    );
    println!();

    println!("\x1b[36m[database]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "type", status.config.database.database_type
    );
    println!();

    println!("\x1b[36m[database.mysql]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "server_url", status.config.database.mysql.server_url
    );
    println!();

    println!("\x1b[36m[database.sqlite]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "file_path", status.config.database.sqlite.file_path
    );
    println!();

    println!("\x1b[36m[database.postgresql]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "server_url", status.config.database.postgresql.server_url
    );
    println!();

    println!("\x1b[36m[dns]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "listen_port", status.config.dns.listen_port
    );
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "secondary_addrs", status.config.dns.secondary_addrs
    );
    println!();

    println!("\x1b[36m[logging]\x1b[0m");
    println!(
        "  \x1b[33m{:<22}\x1b[0m = {}",
        "log_level", status.config.logging.log_level
    );
    Ok(())
}
