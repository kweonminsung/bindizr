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
        /// The host address of the DNS instance (optional)
        host: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get DNS keys
    #[command(
        aliases = ["dns-key", "key", "keys"]
    )]
    DnsKeys {
        /// The key name of the DNS key (optional)
        key_name: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get zones
    #[command(
        aliases = ["zone"]
    )]
    Zones {
        /// The name of the zone (optional)
        name: Option<String>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get records
    #[command(
        aliases = ["record"]
    )]
    Records {
        /// The name of the record (optional)
        name: Option<String>,
        /// The record type (optional, required if name is provided)
        #[arg(short = 't', long)]
        record_type: Option<String>,
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
        GetCommand::Dns { host, output } => {
            let response = if let Some(host) = host {
                client
                    .send_command(DaemonCommandKind::GetDns, Some(json!({ "host": host })))
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
        GetCommand::DnsKeys { key_name, output } => {
            let response = if let Some(key_name) = key_name {
                client
                    .send_command(
                        DaemonCommandKind::GetDnsKey,
                        Some(json!({ "key_name": key_name })),
                    )
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
        GetCommand::Zones { name, output } => {
            let response = if let Some(name) = name {
                client
                    .send_command(DaemonCommandKind::GetZone, Some(json!({ "name": name })))
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
        GetCommand::Records {
            name,
            record_type,
            zone,
            output,
        } => {
            let response = if let Some(name) = name {
                let record_type =
                    record_type.ok_or("record_type is required when name is provided")?;
                client
                    .send_command(
                        DaemonCommandKind::GetRecord,
                        Some(json!({ "name": name, "record_type": record_type })),
                    )
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
