use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    cli::{error::CliError, output::color},
    socket::client,
};

/// Handle the `status` subcommand by querying the daemon and printing its status.
pub(crate) async fn handle_command() -> Result<(), CliError> {
    let status = client::fetch_status().await?;

    println!("=== BINDIZR STATUS ===");
    println!("Status: {}", color::green("Running"));
    let pid = match status.pid {
        Some(pid) => pid.to_string(),
        None => "Unknown".to_string(),
    };
    println!("PID: {}", pid);
    println!("Version: {}", status.version);
    println!("Uptime: {}", display_uptime(status.started_at_ms));
    println!();
    println!(
        "API: {} (authentication {})",
        status.api_url,
        if status.api_authentication {
            "on"
        } else {
            "off"
        }
    );
    println!("DNS: {}", status.dns_addr);
    match (&status.database_error, status.zones) {
        (Some(e), _) => println!("Database: {} ({})", status.database_type, color::red(e)),
        (None, Some(1)) => println!("Database: {} (1 zone)", status.database_type),
        (None, Some(zones)) => println!("Database: {} ({} zones)", status.database_type, zones),
        (None, None) => println!("Database: {}", status.database_type),
    }
    println!("Secondaries: {} configured", status.secondaries);
    Ok(())
}

/// The time since `started_at_ms` in days, hours, minutes, and seconds.
fn display_uptime(started_at_ms: u64) -> String {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let secs = now_ms.saturating_sub(started_at_ms) / 1000;
    let (days, hours, minutes, seconds) = (
        secs / 86_400,
        secs % 86_400 / 3_600,
        secs % 3_600 / 60,
        secs % 60,
    );
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{}s", seconds),
        (0, 0, _) => format!("{}m {}s", minutes, seconds),
        (0, _, _) => format!("{}h {}m", hours, minutes),
        _ => format!("{}d {}h", days, hours),
    }
}
