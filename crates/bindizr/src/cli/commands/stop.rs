use std::time::Duration;

use bindizr_core::outln;
use bindizr_service::types::MessageResponse;

use crate::cli::error::CliError;
use crate::cli::output::OutputFormat;
use crate::cli::{commands, output};
use crate::socket::client;

/// Longer than the daemon's own drain budget plus the delay before it acts on
/// the request, so a maximal drain is not reported as a timeout.
const STOP_DEADLINE: Duration = Duration::from_secs(20);

/// Handle the `stop` subcommand: request shutdown and wait until the daemon
/// removes its socket after draining.
pub(crate) async fn handle_command(output: OutputFormat) -> Result<(), CliError> {
    let (response, socket_file) = client::send_shutdown().await?;

    // The acknowledgement is progress, not the result: the command answers for
    // the daemon having gone, which it waits for below.
    if output == OutputFormat::Table {
        outln!("{}", response.message);
    }

    let stopped = commands::poll_with_deadline(STOP_DEADLINE, async || {
        socket_file.is_gone().await.then_some(())
    })
    .await;

    match stopped {
        Some(()) => {
            // The result is the daemon having gone, said the same in every format.
            let stopped = MessageResponse {
                message: "Bindizr stopped.".to_string(),
            };

            if output == OutputFormat::Table {
                outln!("{}", stopped.message);
            } else {
                output::print_payload(&stopped, output)?;
            }
            Ok(())
        }
        None => Err(CliError::request(format!(
            "Bindizr did not stop within {} seconds",
            STOP_DEADLINE.as_secs()
        ))),
    }
}
