use crate::socket::{client::DaemonSocketClient, dto::DaemonCommandKind};
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum NotifyCommand {
    /// Send NOTIFY messages to secondary servers for a zone
    Zone {
        /// Zone name to notify
        zone_name: String,
    },
}

pub async fn handle_notify(subcommand: &NotifyCommand) -> Result<(), String> {
    match subcommand {
        NotifyCommand::Zone { zone_name } => notify_zone(zone_name).await,
    }
}

async fn notify_zone(zone_name: &str) -> Result<(), String> {
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
