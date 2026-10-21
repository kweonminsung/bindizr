//! Report installation checks as OK, FAIL or SKIP, using daemon state or local startup checks.

mod daemon;
mod offline;

use std::fmt;

use bindizr_core::{config, config::Config, outln};
use serde::Serialize;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, color, print_payload},
    },
    socket::{
        client,
        types::{DaemonCommand, DoctorCheckResponse, DoctorCheckStatus},
    },
};

/// The whole run, as `--output json` reports it.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
struct DoctorResponse {
    healthy: bool,
    failures: usize,
    checks: Vec<DoctorCheckResponse>,
}

/// Collects check outcomes for the exit code, printing each as it lands
/// unless the caller asked for one document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    format: OutputFormat,
    checks: Vec<DoctorCheckResponse>,
    failures: usize,
}

impl Report {
    /// Record a successful diagnostic check.
    pub(crate) fn ok(&mut self, message: impl fmt::Display) {
        self.push(DoctorCheckResponse {
            status: DoctorCheckStatus::Ok,
            message: message.to_string(),
        });
    }

    /// Record a failed diagnostic check.
    pub(crate) fn fail(&mut self, message: impl fmt::Display) {
        self.push(DoctorCheckResponse {
            status: DoctorCheckStatus::Failed,
            message: message.to_string(),
        });
    }

    /// Record a skipped diagnostic check.
    pub(crate) fn skip(&mut self, message: impl fmt::Display) {
        self.push(DoctorCheckResponse {
            status: DoctorCheckStatus::Skipped,
            message: message.to_string(),
        });
    }

    /// Store one check, counting a failure and printing it now in table form.
    pub(crate) fn push(&mut self, check: DoctorCheckResponse) {
        if check.status == DoctorCheckStatus::Failed {
            self.failures += 1;
        }

        if self.format == OutputFormat::Table {
            let text = check.status.to_string();
            let label = match check.status {
                DoctorCheckStatus::Ok => color::green(&text),
                DoctorCheckStatus::Failed => color::red(&text),
                DoctorCheckStatus::Skipped => color::yellow(&text),
            };
            outln!("[{}] {}", label, check.message);
        }

        self.checks.push(check);
    }
}

/// Handle the `doctor` subcommand by verifying the installation end to end.
pub(crate) async fn handle_command(
    config_file: Option<String>,
    format: OutputFormat,
) -> Result<(), CliError> {
    if format == OutputFormat::Table {
        outln!("Bindizr Doctor");
        outln!();
    }

    let mut report = Report {
        format,
        checks: Vec::new(),
        failures: 0,
    };

    let path = config::resolve_config_path(config_file.as_deref());
    let file_config = match Config::load(&path) {
        Ok(config) => {
            report.ok(format!("Config valid: {}", path));
            Some(config)
        }
        Err(error) => {
            report.fail(format!("Config invalid: {}", error));
            None
        }
    };

    if daemon::check_running(&mut report).await {
        let daemon_config = client::send_control_command::<Config>(DaemonCommand::Config)
            .await
            .map(|response| response.data);

        match daemon_config {
            Ok(config) => daemon::check_api(&config, &mut report).await,
            Err(error) => report.fail(format!("Daemon config not readable: {}", error.message)),
        }

        daemon::check_services(&mut report).await;
    } else if let Some(config) = &file_config {
        // What a daemon that failed to start most likely hit.
        report.skip("API check skipped: daemon is not running");
        offline::check_database(config, &mut report).await;
        offline::check_listen_ports(config, &mut report).await;
    } else {
        report.skip("API, database, and port checks skipped: no valid configuration");
    }

    if format == OutputFormat::Table {
        outln!();
        if report.failures == 0 {
            outln!("Result: installation looks {}", color::green("healthy"));
        }
    } else {
        let document = DoctorResponse {
            healthy: report.failures == 0,
            failures: report.failures,
            checks: report.checks,
        };
        print_payload(&document, format)?;
    }

    if report.failures == 0 {
        Ok(())
    } else {
        // To stderr, leaving a JSON document alone on stdout.
        Err(CliError::request(format!(
            "installation has {} failing check(s)",
            report.failures
        )))
    }
}
