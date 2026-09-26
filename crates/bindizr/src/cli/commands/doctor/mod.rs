//! `bindizr doctor`: installation checks reported as OK, FAIL, or SKIP. A
//! running daemon answers for itself; without one, the checks a failed start
//! would have hit run here.

mod daemon;
mod offline;

use std::fmt;

use bindizr_core::{config, config::BindizrConfig, outln};
use serde::Serialize;

use crate::{
    cli::{
        error::CliError,
        output::{OutputFormat, color, parse_payload, print_payload},
    },
    socket::{
        client,
        types::{DaemonCommandKind, DoctorCheck, DoctorCheckStatus},
    },
};

/// The whole run, as `--output json` reports it.
#[derive(Serialize)]
struct DoctorReport {
    healthy: bool,
    failures: usize,
    checks: Vec<DoctorCheck>,
}

/// Collects check outcomes for the exit code, printing each as it lands
/// unless the caller asked for one document.
pub(crate) struct Report {
    format: OutputFormat,
    checks: Vec<DoctorCheck>,
    failures: usize,
}

impl Report {
    /// Record a successful diagnostic check.
    pub(crate) fn ok(&mut self, message: impl fmt::Display) {
        self.push(DoctorCheck {
            status: DoctorCheckStatus::Ok,
            message: message.to_string(),
        });
    }

    /// Record a failed diagnostic check.
    pub(crate) fn fail(&mut self, message: impl fmt::Display) {
        self.push(DoctorCheck {
            status: DoctorCheckStatus::Fail,
            message: message.to_string(),
        });
    }

    /// Record a skipped diagnostic check.
    pub(crate) fn skip(&mut self, message: impl fmt::Display) {
        self.push(DoctorCheck {
            status: DoctorCheckStatus::Skip,
            message: message.to_string(),
        });
    }

    /// Store one check, counting a failure and printing it now in table form.
    pub(crate) fn push(&mut self, check: DoctorCheck) {
        if check.status == DoctorCheckStatus::Fail {
            self.failures += 1;
        }
        if self.format == OutputFormat::Table {
            let label = match check.status {
                DoctorCheckStatus::Ok => color::green("OK"),
                DoctorCheckStatus::Fail => color::red("FAIL"),
                DoctorCheckStatus::Skip => color::yellow("SKIP"),
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
    let file_config = match config::load_config_file(&path) {
        Ok(config) => {
            report.ok(format!("Config valid: {}", path));
            Some(config)
        }
        Err(e) => {
            report.fail(format!("Config invalid: {}", e));
            None
        }
    };
    if daemon::check_running(&mut report).await {
        let daemon_config = client::send_control_command(DaemonCommandKind::Config)
            .await
            .and_then(|response| Ok(parse_payload::<BindizrConfig>(&response.data)?));
        match daemon_config {
            Ok(config) => daemon::check_api(&config, &mut report).await,
            Err(e) => report.fail(format!("Daemon config not readable: {}", e.message)),
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
        let document = DoctorReport {
            healthy: report.failures == 0,
            failures: report.failures,
            checks: report.checks,
        };
        let value = serde_json::to_value(&document)
            .map_err(|e| format!("Failed to render the report: {}", e))?;
        print_payload(&value, format)?;
    }

    if report.failures == 0 {
        Ok(())
    } else {
        // To stderr, leaving a JSON document alone on stdout.
        Err(CliError::from(format!(
            "installation has {} failing check(s)",
            report.failures
        )))
    }
}
