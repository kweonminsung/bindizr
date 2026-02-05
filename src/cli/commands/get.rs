use crate::cli::output::{
    DnsInstanceRow, DnsKeyRow, OutputFormat, RecordRow, ZoneRow, print_output_with_table,
};
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
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get DNS keys
    DnsKeys {
        /// The ID of the DNS key (optional)
        id: Option<i32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get zones
    Zones {
        /// The ID of the zone (optional)
        id: Option<i32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get records
    Records {
        /// The ID of the record (optional)
        id: Option<i32>,
        /// Filter by zone ID
        #[arg(short, long)]
        zone: Option<i32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

pub async fn handle_command(subcommand: GetCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        GetCommand::Dns { id, output } => {
            let response = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetDns, Some(json!({ "id": id })))
                    .await?
            } else {
                client
                    .send_command(DaemonCommandKind::ListDns, None)
                    .await?
            };

            print_output_with_table(&response.data, output, |data| {
                if let Some(arr) = data.as_array() {
                    arr.iter()
                        .filter_map(|v| DnsInstanceRow::from_json(v).ok())
                        .collect()
                } else {
                    vec![
                        DnsInstanceRow::from_json(data)
                            .unwrap_or_else(|_| panic!("Failed to parse DNS instance")),
                    ]
                }
            })?;
        }
        GetCommand::DnsKeys { id, output } => {
            let response = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetDnsKey, Some(json!({ "id": id })))
                    .await?
            } else {
                client
                    .send_command(DaemonCommandKind::ListDnsKeys, None)
                    .await?
            };

            print_output_with_table(&response.data, output, |data| {
                if let Some(arr) = data.as_array() {
                    arr.iter()
                        .filter_map(|v| DnsKeyRow::from_json(v).ok())
                        .collect()
                } else {
                    vec![
                        DnsKeyRow::from_json(data)
                            .unwrap_or_else(|_| panic!("Failed to parse DNS key")),
                    ]
                }
            })?;
        }
        GetCommand::Zones { id, output } => {
            let response = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetZone, Some(json!({ "id": id })))
                    .await?
            } else {
                client
                    .send_command(DaemonCommandKind::ListZones, None)
                    .await?
            };

            print_output_with_table(&response.data, output, |data| {
                if let Some(arr) = data.as_array() {
                    arr.iter()
                        .filter_map(|v| ZoneRow::from_json(v).ok())
                        .collect()
                } else {
                    vec![
                        ZoneRow::from_json(data).unwrap_or_else(|_| panic!("Failed to parse zone")),
                    ]
                }
            })?;
        }
        GetCommand::Records { id, zone, output } => {
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

            print_output_with_table(&response.data, output, |data| {
                if let Some(arr) = data.as_array() {
                    arr.iter()
                        .filter_map(|v| RecordRow::from_json(v).ok())
                        .collect()
                } else {
                    vec![
                        RecordRow::from_json(data)
                            .unwrap_or_else(|_| panic!("Failed to parse record")),
                    ]
                }
            })?;
        }
    }

    Ok(())
}
