use crate::daemon;

/// Handle the `start` subcommand by bootstrapping the daemon in the foreground.
pub(crate) async fn handle_command(config: Option<String>) -> Result<(), String> {
    daemon::bootstrap(config.as_deref()).await
}
