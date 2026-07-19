use clap::Subcommand;
use serde_json::json;

use crate::{
    cli::output::{OutputFormat, RecordRow, ZoneRow, print_output_with_table},
    socket::{client::DaemonSocketClient, types::DaemonCommandKind},
};

/// Subcommands for reading zones and records.
#[derive(Subcommand, Debug)]
pub(crate) enum GetCommand {
    /// Get zones
    #[command(
        aliases = ["zone"]
    )]
    Zones {
        /// The name of the zone (optional)
        name: Option<String>,
        /// Filter by zone ID
        #[arg(long)]
        id: Option<i64>,
        /// Filter by primary name server
        #[arg(long)]
        primary_ns: Option<String>,
        /// Filter by admin email
        #[arg(long)]
        admin_email: Option<String>,
        /// Filter by TTL
        #[arg(long)]
        ttl: Option<i64>,
        /// Filter by minimum TTL
        #[arg(long)]
        min_ttl: Option<i64>,
        /// Filter by maximum TTL
        #[arg(long)]
        max_ttl: Option<i64>,
        /// Filter by serial
        #[arg(long)]
        serial: Option<i64>,
        /// Search zones by partial text
        #[arg(short = 'q', long)]
        search: Option<String>,
        /// Maximum number of zones to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of zones to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Get records
    #[command(
        aliases = ["record"]
    )]
    Records {
        /// The record ID (optional)
        id: Option<i32>,
        /// Filter by zone name
        #[arg(short, long)]
        zone: Option<String>,
        /// Filter by record name
        #[arg(long)]
        name: Option<String>,
        /// Filter by record type
        #[arg(long = "type", alias = "record-type")]
        record_type: Option<String>,
        /// Filter by record value
        #[arg(long)]
        value: Option<String>,
        /// Filter by TTL
        #[arg(long)]
        ttl: Option<i64>,
        /// Filter by minimum TTL
        #[arg(long)]
        min_ttl: Option<i64>,
        /// Filter by maximum TTL
        #[arg(long)]
        max_ttl: Option<i64>,
        /// Filter by priority
        #[arg(long)]
        priority: Option<i64>,
        /// Filter by minimum priority
        #[arg(long)]
        min_priority: Option<i64>,
        /// Filter by maximum priority
        #[arg(long)]
        max_priority: Option<i64>,
        /// Search records by partial text
        #[arg(short = 'q', long)]
        search: Option<String>,
        /// Maximum number of records to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of records to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

/// Handle the `get` subcommand by querying the daemon and printing the results.
pub(crate) async fn handle_command(subcommand: GetCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        GetCommand::Zones {
            name,
            id,
            primary_ns,
            admin_email,
            ttl,
            min_ttl,
            max_ttl,
            serial,
            search,
            limit,
            offset,
            output,
        } => {
            let has_filters = id.is_some()
                || primary_ns.is_some()
                || admin_email.is_some()
                || ttl.is_some()
                || min_ttl.is_some()
                || max_ttl.is_some()
                || serial.is_some()
                || search.is_some()
                || limit.is_some()
                || offset.is_some();
            let filter_payload = || {
                json!({
                    "name": name,
                    "id": id,
                    "primary_ns": primary_ns,
                    "admin_email": admin_email,
                    "ttl": ttl,
                    "min_ttl": min_ttl,
                    "max_ttl": max_ttl,
                    "serial": serial,
                    "search": search,
                    "limit": limit,
                    "offset": offset,
                })
            };
            let data = if let Some(name) = name.as_deref() {
                if has_filters {
                    client
                        .send_command(DaemonCommandKind::ListZones, Some(filter_payload()))
                        .await?
                        .data
                } else {
                    client
                        .send_command(DaemonCommandKind::GetZone, Some(json!({ "name": name })))
                        .await?
                        .data
                }
            } else {
                client
                    .send_command(
                        DaemonCommandKind::ListZones,
                        has_filters.then(filter_payload),
                    )
                    .await?
                    .data
            };

            print_output_with_table(&data, output, |data| {
                if let Some(arr) = data.get("items").and_then(|value| value.as_array()) {
                    Ok(arr
                        .iter()
                        .filter_map(|v| ZoneRow::from_json(v).ok())
                        .collect())
                } else {
                    ZoneRow::from_json(data)
                        .map(|row| vec![row])
                        .map_err(|e| format!("Failed to parse zone: {}", e))
                }
            })?;
        }
        GetCommand::Records {
            id,
            zone,
            name,
            record_type,
            value,
            ttl,
            min_ttl,
            max_ttl,
            priority,
            min_priority,
            max_priority,
            search,
            limit,
            offset,
            output,
        } => {
            let has_filters = zone.is_some()
                || name.is_some()
                || record_type.is_some()
                || value.is_some()
                || ttl.is_some()
                || min_ttl.is_some()
                || max_ttl.is_some()
                || priority.is_some()
                || min_priority.is_some()
                || max_priority.is_some()
                || search.is_some()
                || limit.is_some()
                || offset.is_some();
            let filter_payload = || {
                json!({
                    "zone_name": zone,
                    "name": name,
                    "record_type": record_type,
                    "value": value,
                    "ttl": ttl,
                    "min_ttl": min_ttl,
                    "max_ttl": max_ttl,
                    "priority": priority,
                    "min_priority": min_priority,
                    "max_priority": max_priority,
                    "search": search,
                    "limit": limit,
                    "offset": offset,
                })
            };

            let data = if let Some(id) = id {
                client
                    .send_command(DaemonCommandKind::GetRecord, Some(json!({ "id": id })))
                    .await?
                    .data
            } else if has_filters {
                client
                    .send_command(DaemonCommandKind::ListRecords, Some(filter_payload()))
                    .await?
                    .data
            } else {
                client
                    .send_command(DaemonCommandKind::ListRecords, None)
                    .await?
                    .data
            };

            print_output_with_table(&data, output, |data| {
                if let Some(arr) = data.get("items").and_then(|value| value.as_array()) {
                    Ok(arr
                        .iter()
                        .filter_map(|v| RecordRow::from_json(v).ok())
                        .collect())
                } else {
                    RecordRow::from_json(data)
                        .map(|row| vec![row])
                        .map_err(|e| format!("Failed to parse record: {}", e))
                }
            })?;
        }
    }

    Ok(())
}
