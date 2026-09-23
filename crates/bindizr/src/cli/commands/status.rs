use std::time::{SystemTime, UNIX_EPOCH};

use bindizr_core::outln;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, color, parse_response, print_payload},
    },
    socket::{
        client,
        types::{DaemonCommandKind, DaemonStatusResponse},
    },
};

/// Handle the `status` subcommand by querying the daemon and printing its status.
pub(crate) async fn handle_command(output: OutputFormat) -> Result<(), CliError> {
    let response = client::send_control_command(DaemonCommandKind::Status).await?;
    let status: DaemonStatusResponse = parse_response(&response.data)?;

    match output {
        OutputFormat::Table => {
            outln!("=== BINDIZR STATUS ===");
            outln!("Status: {}", color::green("Running"));
            let pid = match status.pid {
                Some(pid) => pid.to_string(),
                None => "Unknown".to_string(),
            };
            outln!("PID: {}", pid);
            outln!("Version: {}", status.version);
            outln!("Uptime: {}", display_uptime(status.started_at_ms));
            outln!();
            outln!(
                "API: {} (authentication {})",
                status.api_url,
                if status.api_authentication {
                    "on"
                } else {
                    "off"
                }
            );
            outln!("DNS: {}", status.dns_addr);
            match (&status.database_error, status.zones) {
                (Some(e), _) => outln!("Database: {} ({})", status.database_type, color::red(e)),
                (None, Some(1)) => outln!("Database: {} (1 zone)", status.database_type),
                (None, Some(zones)) => {
                    outln!("Database: {} ({} zones)", status.database_type, zones)
                }
                (None, None) => outln!("Database: {}", status.database_type),
            }
            match status.secondaries {
                Some(1) => outln!("Secondaries: 1 enabled"),
                Some(secondaries) => outln!("Secondaries: {} enabled", secondaries),
                None => {}
            }
        }
        _ => print_payload(&response.data, output)?,
    }

    // A daemon whose database does not answer is not healthy, so the exit code
    // says so for a health wrapper and the container health check.
    match status.database_error {
        Some(error) => Err(CliError::from(format!("Database unavailable: {}", error))),
        None => Ok(()),
    }
}

/// The time since `started_at_ms` in days, hours, minutes, and seconds. The
/// start time is stamped once every front end is up, so an unset one means the
/// daemon is still starting.
fn display_uptime(started_at_ms: u64) -> String {
    if started_at_ms == 0 {
        return "starting".to_string();
    }
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
