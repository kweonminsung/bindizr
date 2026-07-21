use clap::{Args, Subcommand};
use serde_json::json;

use crate::{
    cli::output::{OutputFormat, ZoneRow, print_output_with_table},
    socket::{client::DaemonSocketClient, types::DaemonCommandKind},
};

/// Subcommands for managing zones.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneCommand {
    /// Create a zone
    Create {
        /// Zone name
        #[arg(long)]
        name: String,
        /// Primary nameserver
        #[arg(long)]
        primary_ns: String,
        /// Admin email
        #[arg(long)]
        admin_email: String,
        /// TTL
        #[arg(long)]
        ttl: i32,
        /// Serial number (optional, auto-generated if not provided)
        #[arg(long)]
        serial: Option<i32>,
    },

    /// List zones
    #[command(alias = "ls")]
    List {
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

    /// Get a zone by name
    Get {
        /// The name of the zone
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Delete a zone
    Delete {
        /// The name of the zone
        name: String,
    },

    /// Send NOTIFY messages to secondary servers for a zone
    Notify(NotifyArgs),
}

/// Arguments for the `zone notify` subcommand.
#[derive(Args, Debug)]
pub(crate) struct NotifyArgs {
    /// Force serial increment before sending NOTIFY
    #[arg(short, long)]
    force: bool,

    /// Zone name to notify (optional: if not specified, notifies all zones)
    name: Option<String>,
}

/// Handle the `zone` subcommand by forwarding it to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: ZoneCommand) -> Result<(), String> {
    let client = DaemonSocketClient::new();

    match subcommand {
        ZoneCommand::Create {
            name,
            primary_ns,
            admin_email,
            ttl,
            serial,
        } => {
            let data = json!({
                "name": name,
                "primary_ns": primary_ns,
                "admin_email": admin_email,
                "ttl": ttl,
                "serial": serial,
            });
            let response = client
                .send_command(DaemonCommandKind::CreateZone, Some(data))
                .await?;
            println!("{}", response.message);
        }
        ZoneCommand::List {
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
            let data = client
                .send_command(
                    DaemonCommandKind::ListZones,
                    has_filters.then(filter_payload),
                )
                .await?
                .data;

            print_zones(&data, output)?;
        }
        ZoneCommand::Get { name, output } => {
            let data = client
                .send_command(DaemonCommandKind::GetZone, Some(json!({ "name": name })))
                .await?
                .data;

            print_zones(&data, output)?;
        }
        ZoneCommand::Delete { name } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteZone, Some(json!({ "name": name })))
                .await?;
            println!("{}", response.message);
        }
        ZoneCommand::Notify(args) => {
            let response = client
                .send_command(
                    DaemonCommandKind::NotifyZone,
                    Some(json!({
                        "zone_name": args.name,
                        "force": args.force
                    })),
                )
                .await?;
            println!("{}", response.message);
        }
    }

    Ok(())
}

fn print_zones(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    print_output_with_table(data, output, |data| {
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
    })
}
