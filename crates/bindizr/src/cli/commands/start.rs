use crate::cli::bootstrap;

/// Handle the `start` subcommand by bootstrapping the service in the foreground.
pub(crate) async fn handle_command(config: Option<String>) -> Result<(), String> {
    bootstrap(config.as_deref()).await
}
