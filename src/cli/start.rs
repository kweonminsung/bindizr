use crate::cli::bootstrap;

pub async fn handle_command(config: Option<String>) -> Result<(), String> {
    bootstrap(config.as_deref()).await
}
