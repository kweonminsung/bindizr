use crate::socket::client::DaemonSocketClient;
use crate::socket::dto::DaemonCommandKind;
use clap::Subcommand;
use serde_json::json;

#[derive(Subcommand, Debug)]
pub enum GetCommand {
    /// Get DNS instances
    Dns {
        /// The ID of the DNS instance (optional)
        id: Option<i32>,
    },

    /// Get DNS keys
    DnsKeys {
        /// The ID of the DNS key (optional)
        id: Option<i32>,
    },

    /// Get zones
    Zones {
        /// The ID of the zone (optional)
        id: Option<i32>,
    },

    /// Get records
    Records {
        /// The ID of the record (optional)
        id: Option<i32>,
        /// Filter by zone ID
        #[arg(short, long)]
        zone: Option<i32>,
    },
}

pub async fn handle_command(subcommand: GetCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        GetCommand::Dns { id } => {
            let response = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetDns, Some(json!({ "id": id })))
                    .await?
            } else {
                client
                    .send_command(DaemonCommandKind::ListDns, None)
                    .await?
            };
            println!("{}", serde_json::to_string_pretty(&response.data).unwrap());
        }
        GetCommand::DnsKeys { id } => {
            let response = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetDnsKey, Some(json!({ "id": id })))
                    .await?
            } else {
                client
                    .send_command(DaemonCommandKind::ListDnsKeys, None)
                    .await?
            };
            println!("{}", serde_json::to_string_pretty(&response.data).unwrap());
        }
        GetCommand::Zones { id } => {
            let response = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetZone, Some(json!({ "id": id })))
                    .await?
            } else {
                client
                    .send_command(DaemonCommandKind::ListZones, None)
                    .await?
            };
            println!("{}", serde_json::to_string_pretty(&response.data).unwrap());
        }
        GetCommand::Records { id, zone } => {
            let response = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetRecord, Some(json!({ "id": id })))
                    .await?
            } else if let Some(zone_id) = zone {
                client
                    .send_command(
                        DaemonCommandKind::ListRecords,
                        Some(json!({ "zone_id": zone_id })),
                    )
                    .await?
            } else {
                client
                    .send_command(DaemonCommandKind::ListRecords, None)
                    .await?
            };
            println!("{}", serde_json::to_string_pretty(&response.data).unwrap());
        }
    }

    Ok(())
}
