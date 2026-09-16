//! Completion scripts and the man page, generated from the clap command the
//! binary parses with, so they cannot drift from `--help`.

use std::io::{self, ErrorKind, Write};

use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::{Args, error::CliError};

/// Print the completion script for `shell` on stdout.
pub(crate) fn handle_command(shell: Shell) -> Result<(), CliError> {
    let mut command = Args::command();
    let name = command.get_name().to_string();
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut command, name, &mut script);
    write_stdout(&script)
}

/// Print the roff man page for `bindizr` on stdout.
pub(crate) fn handle_man_command() -> Result<(), CliError> {
    let mut page = Vec::new();
    clap_mangen::Man::new(Args::command())
        .render(&mut page)
        .map_err(|e| CliError::from(format!("Failed to render the man page: {}", e)))?;
    write_stdout(&page)
}

/// Write to stdout, counting a closed pipe as success: both commands are made
/// to be piped.
fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    match io::stdout().write_all(bytes) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(CliError::from(format!("Failed to write to stdout: {}", e))),
    }
}
