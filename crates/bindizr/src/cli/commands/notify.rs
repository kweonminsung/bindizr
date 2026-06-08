use clap::{Args, Subcommand};
use serde_json::json;

use crate::socket::{client::DaemonSocketClient, types::DaemonCommandKind};

#[derive(Subcommand, Debug)]
pub(crate) enum NotifyCommand {
    /// Send NOTIFY messages to secondary servers for a zone
    Zone(NotifyZoneArgs),
}

#[derive(Args, Debug)]
pub(crate) struct NotifyZoneArgs {
    /// Force serial increment before sending NOTIFY
    #[arg(short, long)]
    force: bool,

    /// Zone name to notify (optional: if not specified, notifies all zones)
    zone_name: Option<String>,
}

pub(crate) async fn handle_notify(subcommand: &NotifyCommand) -> Result<(), String> {
    match subcommand {
        NotifyCommand::Zone(args) => notify_zone(args.zone_name.as_deref(), args.force).await,
    }
}

async fn notify_zone(zone_name: Option<&str>, force: bool) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    let response = client
        .send_command(
            DaemonCommandKind::NotifyZone,
            Some(json!({
                "zone_name": zone_name,
                "force": force
            })),
        )
        .await?;

    println!("{}", response.message);
    Ok(())
}
