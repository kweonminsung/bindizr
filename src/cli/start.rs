use crate::{cli::bootstrap, daemon::process};

pub async fn handle_command(
    foreground: bool,
    config: Option<String>,
    silent: bool,
) -> Result<(), String> {
    if foreground {
        // Run in foreground mode
        if silent {
            // Silent mode
            bootstrap(true, config.as_deref()).await?;
        } else {
            bootstrap(false, config.as_deref()).await?;
        }
    } else {
        // Run in background mode
        process::start();
    }

    Ok(())
}
