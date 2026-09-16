use crate::{
    cli::error::CliError,
    socket::{
        client,
        types::{DaemonCommandKind, NotifyAllZonesParams},
    },
};

/// Handle the `notify` subcommand by asking the daemon to NOTIFY every zone.
pub(crate) async fn handle_command(bump_serial: bool) -> Result<(), CliError> {
    let response = client::send_command(
        DaemonCommandKind::NotifyAllZones,
        NotifyAllZonesParams { bump_serial },
    )
    .await?;
    println!("{}", response.message);
    Ok(())
}
