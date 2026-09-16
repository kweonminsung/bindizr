//! `bindizr doctor`: installation checks reported as OK, FAIL, or SKIP. A
//! running daemon answers for itself; without one, the checks a failed start
//! would have hit run here.

mod bind;
mod daemon;
mod offline;

use std::fmt;

use bindizr_core::config;

use crate::{
    cli::{error::CliError, output::color},
    socket::client,
};

/// Tallies check outcomes so the exit code can reflect them.
pub(crate) struct Report {
    failures: usize,
}

impl Report {
    /// Print a successful diagnostic check.
    pub(crate) fn ok(&mut self, message: impl fmt::Display) {
        println!("[{}] {}", color::green("OK"), message);
    }

    /// Print a failed diagnostic check and increment the failure count.
    pub(crate) fn fail(&mut self, message: impl fmt::Display) {
        self.failures += 1;
        println!("[{}] {}", color::red("FAIL"), message);
    }

    /// Print a skipped diagnostic check.
    pub(crate) fn skip(&mut self, message: impl fmt::Display) {
        println!("[{}] {}", color::yellow("SKIP"), message);
    }
}

/// Handle the `doctor` subcommand by verifying the installation end to end.
pub(crate) async fn handle_command(config_file: Option<String>) -> Result<(), CliError> {
    println!("Bindizr Doctor");
    println!();

    let mut report = Report { failures: 0 };

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
        match client::fetch_config().await {
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
    bind::check_catalog(
        file_config.as_ref().map(|config| config.dns.listen_port),
        &mut report,
    );

    println!();
    if report.failures == 0 {
        println!("Result: installation looks {}", color::green("healthy"));
        Ok(())
    } else {
        Err(CliError::from(format!(
            "installation has {} failing check(s)",
            report.failures
        )))
    }
}
