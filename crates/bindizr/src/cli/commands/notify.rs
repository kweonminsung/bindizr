use clap::Subcommand;
use serde_json::json;

use crate::socket::{client::DaemonSocketClient, types::DaemonCommandKind};

#[derive(Subcommand, Debug)]
pub(crate) enum NotifyCommand {
    /// Send NOTIFY messages to secondary servers for a zone
    Zone {
        /// Zone name to notify (optional: if not specified, notifies all zones)
        zone_name: Option<String>,
    },
}

pub(crate) async fn handle_notify(subcommand: &NotifyCommand) -> Result<(), String> {
    match subcommand {
        NotifyCommand::Zone { zone_name } => notify_zone(zone_name.as_deref()).await,
    }
}

async fn notify_zone(zone_name: Option<&str>) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    let response = client
        .send_command(
            DaemonCommandKind::NotifyZone,
            Some(json!({
                "zone_name": zone_name
            })),
        )
        .await?;

    println!("{}", response.message);
    Ok(())
}
