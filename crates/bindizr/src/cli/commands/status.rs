use bindizr_core::outln;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, color, display_uptime, print_payload},
    },
    socket::{
        client,
        types::{DaemonCommand, DaemonStatusResponse},
    },
};

/// Handle the `status` subcommand by querying the daemon and printing its status.
pub(crate) async fn handle_command(output: OutputFormat) -> Result<(), CliError> {
    let status = client::send_control_command::<DaemonStatusResponse>(DaemonCommand::Status)
        .await?
        .data;

    match output {
        OutputFormat::Table => {
            outln!("=== BINDIZR STATUS ===");
            outln!("Status: {}", color::green("Running"));
            let pid = match status.pid {
                Some(pid) => pid.to_string(),
                None => "unknown".to_string(),
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
        _ => print_payload(&status, output)?,
    }

    // A daemon whose database does not answer is not healthy, so the exit code
    // says so for a health wrapper and the container health check.
    match status.database_error {
        Some(error) => Err(CliError::request(format!(
            "Database unavailable: {}",
            error
        ))),
        None => Ok(()),
    }
}
