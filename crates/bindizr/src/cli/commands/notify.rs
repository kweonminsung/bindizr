use crate::{
    cli::error::CliError,
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, NotifyAllZonesParams},
    },
};

/// Handle the `notify` subcommand by asking the daemon to NOTIFY every zone.
pub(crate) async fn handle_command(bump_serial: bool) -> Result<(), CliError> {
    let response = DaemonSocketClient::new()
        .send_command(
            DaemonCommandKind::NotifyAllZones,
            NotifyAllZonesParams { bump_serial },
        )
        .await?;
    println!("{}", response.message);
    Ok(())
}
