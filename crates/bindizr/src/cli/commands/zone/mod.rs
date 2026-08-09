//! The `zone` subcommands. Each nested family owns its own grammar, dispatch,
//! and output rendering in a sibling module.

mod snapshot;
mod token_policy;
mod tsig_policy;

use bindizr_service::types::{
    CreateZoneRequest, GetZonesFilter, ImportMode as ServiceImportMode, ImportZoneFileRequest,
    NotifyZoneRequest, UpdateZonePatch,
};
use clap::{Args, Subcommand, ValueEnum};
pub(crate) use snapshot::ZoneSnapshotCommand;
pub(crate) use token_policy::ZoneTokenPolicyCommand;
pub(crate) use tsig_policy::ZoneTsigPolicyCommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            ImportSummaryRow, OutputFormat, SecondaryStatusRow, ZoneRow, print_output_with_table,
            render_change_preview,
        },
    },
    socket::{
        client::DaemonSocketClient,
        types::{DaemonCommandKind, ImportZoneFileParams, UpdateZoneParams, ZoneNameParams},
    },
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
        /// Starting serial, 1-2137483647 (optional, auto-generated if not provided)
        #[arg(long)]
        serial: Option<i32>,
    },

    /// Update a zone, changing only the fields you pass
    Update {
        /// The name of the zone to update
        name: String,
        /// Rename the zone to this name
        #[arg(long)]
        new_name: Option<String>,
        /// Primary nameserver
        #[arg(long)]
        primary_ns: Option<String>,
        /// Admin email
        #[arg(long)]
        admin_email: Option<String>,
        /// TTL
        #[arg(long)]
        ttl: Option<i32>,
        /// SOA refresh interval (seconds)
        #[arg(long)]
        refresh: Option<i32>,
        /// SOA retry interval (seconds)
        #[arg(long)]
        retry: Option<i32>,
        /// SOA expire interval (seconds)
        #[arg(long)]
        expire: Option<i32>,
        /// SOA minimum TTL (seconds)
        #[arg(long)]
        minimum_ttl: Option<i32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// List zones
    #[command(alias = "ls")]
    List {
        /// Filter by zone name
        #[arg(long)]
        name: Option<String>,
        /// Filter by zone ID
        #[arg(long)]
        id: Option<i32>,
        /// Filter by primary name server
        #[arg(long)]
        primary_ns: Option<String>,
        /// Filter by admin email
        #[arg(long)]
        admin_email: Option<String>,
        /// Filter by TTL
        #[arg(long)]
        ttl: Option<i32>,
        /// Filter by minimum TTL
        #[arg(long)]
        min_ttl: Option<i32>,
        /// Filter by maximum TTL
        #[arg(long)]
        max_ttl: Option<i32>,
        /// Filter by serial
        #[arg(long)]
        serial: Option<i32>,
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

    /// Import a BIND zone file into a zone
    #[command(after_help = "\
The file is standard BIND zone file text, for example:
  www    300  IN A   192.0.2.1
  mail        IN A   192.0.2.2
  @           IN MX  10 mail.example.com.

Relative names resolve against the zone and missing TTLs fall back to the
zone TTL. SOA lines are ignored (SOA metadata is managed by bindizr) and
$INCLUDE is not supported.")]
    Import {
        /// The name of the zone
        name: String,
        /// Path to a BIND zone file, or '-' to read from stdin
        file: String,
        /// How parsed records are reconciled with existing records
        #[arg(long, value_enum, default_value_t = ImportMode::Append)]
        mode: ImportMode,
        /// Parse and validate without applying any change
        #[arg(long)]
        dry_run: bool,
        /// Preview the change as a +/-/~ diff without applying it (implies --dry-run)
        #[arg(long)]
        preview: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Export a zone as BIND master-file text
    Export {
        /// The name of the zone
        name: String,
    },

    /// Inspect or roll back a zone's snapshots (serial history)
    Snapshot {
        #[command(subcommand)]
        subcommand: ZoneSnapshotCommand,
    },

    /// Show how far each secondary has caught up with a zone
    Status {
        /// The name of the zone
        name: String,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Send NOTIFY messages to secondary servers for a zone
    Notify(NotifyArgs),

    /// Manage a zone's TSIG policies (which keys may nsupdate what)
    TsigPolicy {
        #[command(subcommand)]
        subcommand: ZoneTsigPolicyCommand,
    },

    /// Manage a zone's API token policies (which tokens may change what)
    TokenPolicy {
        #[command(subcommand)]
        subcommand: ZoneTokenPolicyCommand,
    },
}

/// How `zone import` reconciles parsed records with the records already in the
/// zone. Mirrors the service-layer `ImportMode`; serialized as its lowercase
/// wire name.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ImportMode {
    /// Add parsed records; records already present are left untouched
    Append,
    /// Replace every RRset (name + type) that appears in the file
    Upsert,
    /// Replace all non-protected records in the zone
    Replace,
}

impl From<ImportMode> for ServiceImportMode {
    fn from(mode: ImportMode) -> Self {
        match mode {
            ImportMode::Append => ServiceImportMode::Append,
            ImportMode::Upsert => ServiceImportMode::Upsert,
            ImportMode::Replace => ServiceImportMode::Replace,
        }
    }
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
pub(crate) async fn handle_command(subcommand: ZoneCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    match subcommand {
        ZoneCommand::Create {
            name,
            primary_ns,
            admin_email,
            ttl,
            serial,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::CreateZone,
                    CreateZoneRequest {
                        name,
                        primary_ns,
                        admin_email,
                        ttl,
                        serial,
                        refresh: None,
                        retry: None,
                        expire: None,
                        minimum_ttl: None,
                    },
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneCommand::List {
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
            let has_filters = name.is_some()
                || id.is_some()
                || primary_ns.is_some()
                || admin_email.is_some()
                || ttl.is_some()
                || min_ttl.is_some()
                || max_ttl.is_some()
                || serial.is_some()
                || search.is_some()
                || limit.is_some()
                || offset.is_some();
            let filter_payload = || GetZonesFilter {
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
                .send_command(DaemonCommandKind::GetZone, ZoneNameParams { name })
                .await?
                .data;

            print_zones(&data, output)?;
        }
        ZoneCommand::Update {
            name,
            new_name,
            primary_ns,
            admin_email,
            ttl,
            refresh,
            retry,
            expire,
            minimum_ttl,
            output,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::UpdateZone,
                    // `name` looks up the zone; `new_name` renames it.
                    UpdateZoneParams {
                        name,
                        patch: UpdateZonePatch {
                            new_name,
                            primary_ns,
                            admin_email,
                            ttl,
                            refresh,
                            retry,
                            expire,
                            minimum_ttl,
                            serial: None,
                        },
                    },
                )
                .await?
                .data;

            print_zones(&data, output)?;
        }
        ZoneCommand::Delete { name } => {
            let response = client
                .send_command(DaemonCommandKind::DeleteZone, ZoneNameParams { name })
                .await?;
            println!("{}", response.message);
        }
        ZoneCommand::Export { name } => {
            let data = client
                .send_command(DaemonCommandKind::ExportZoneFile, ZoneNameParams { name })
                .await?
                .data;
            let zone_file = data
                .get("zone_file")
                .and_then(|v| v.as_str())
                .ok_or("Missing zone_file in response")?;
            print!("{}", zone_file);
        }
        ZoneCommand::Import {
            name,
            file,
            mode,
            dry_run,
            preview,
            output,
        } => {
            let content = super::read_input(&file)?;
            let response = client
                .send_command(
                    DaemonCommandKind::ImportZoneFile,
                    ImportZoneFileParams {
                        zone_name: name,
                        request: ImportZoneFileRequest {
                            content,
                            mode: mode.into(),
                            // Preview never applies; it is a dry run rendered as a diff.
                            dry_run: dry_run || preview,
                        },
                    },
                )
                .await?;

            if output == OutputFormat::Table {
                let errors: Vec<&str> = response
                    .data
                    .get("errors")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|e| e.as_str()).collect())
                    .unwrap_or_default();
                if errors.is_empty() {
                    println!("{}", response.message);
                } else {
                    eprintln!("{}", response.message);
                    for error in errors {
                        eprintln!("  - {}", error);
                    }
                }
            }

            if preview && output == OutputFormat::Table {
                let entries = response
                    .data
                    .get("diff")
                    .and_then(|d| d.get("entries"))
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                print!("{}", render_change_preview(&entries));
            } else {
                print_output_with_table(&response.data, output, |data| {
                    data.get("summary")
                        .ok_or("Missing import summary in response".to_string())
                        .and_then(ImportSummaryRow::from_json)
                        .map(|row| vec![row])
                })?;
            }
        }
        ZoneCommand::Snapshot { subcommand } => {
            snapshot::handle_command(&client, subcommand).await?
        }
        ZoneCommand::Status { name, output } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneStatus, ZoneNameParams { name })
                .await?;

            if output == OutputFormat::Table {
                let zone = response.data.get("zone").and_then(|v| v.as_str());
                let serial = response.data.get("serial").and_then(|v| v.as_i64());
                if let (Some(zone), Some(serial)) = (zone, serial) {
                    println!("Zone {} (serial {})", zone, serial);
                }
                let has_secondaries = response
                    .data
                    .get("secondaries")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| !arr.is_empty());
                if !has_secondaries {
                    println!("No secondaries configured.");
                    return Ok(());
                }
            }
            print_output_with_table(&response.data, output, |data| {
                SecondaryStatusRow::rows_from_status(data)
            })?;
        }
        ZoneCommand::Notify(args) => {
            let response = client
                .send_command(
                    DaemonCommandKind::NotifyZone,
                    NotifyZoneRequest {
                        zone_name: args.name,
                        force: args.force,
                    },
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneCommand::TokenPolicy { subcommand } => {
            token_policy::handle_command(&client, subcommand).await?
        }
        ZoneCommand::TsigPolicy { subcommand } => {
            tsig_policy::handle_command(&client, subcommand).await?
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
