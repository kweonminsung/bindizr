use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;

use crate::{
    cli::{
        error::CliError,
        output::{
            ImportSummaryRow, OutputFormat, RollbackSummaryRow, SecondaryStatusRow,
            SnapshotRecordRow, SnapshotRow, ZoneRow, print_output_with_table,
        },
    },
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
        /// Starting serial, 1-2137483647 (optional, auto-generated if not provided)
        #[arg(long)]
        serial: Option<i32>,
    },

    /// List zones
    #[command(alias = "ls")]
    List {
        /// Filter by zone name
        #[arg(long)]
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
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },

    /// Inspect a zone's snapshots (serial history)
    Snapshot {
        #[command(subcommand)]
        subcommand: ZoneSnapshotCommand,
    },

    /// Roll a zone back to the state captured at a snapshot serial
    Rollback {
        /// The name of the zone
        name: String,
        /// Target snapshot serial (the zone serial still advances)
        serial: i32,
        /// Compute and report the rollback without applying any change
        #[arg(long)]
        dry_run: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
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
}

/// Subcommands for inspecting a zone's snapshots.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneSnapshotCommand {
    /// List a zone's snapshots (serial history)
    #[command(alias = "ls")]
    List {
        /// The name of the zone
        name: String,
        /// Maximum number of snapshots to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of snapshots to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Show the zone state captured at one snapshot serial
    Get {
        /// The name of the zone
        name: String,
        /// Snapshot serial to inspect
        serial: i32,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
}

/// Subcommands for managing a zone's TSIG policies.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneTsigPolicyCommand {
    /// Grant a TSIG key nsupdate rights in a zone
    Add {
        /// The name of the zone
        name: String,
        /// Name of an existing non-global TSIG key (global keys already cover
        /// every zone)
        #[arg(long)]
        key: String,
        /// Record name pattern: '*' (any), '@' (apex), '*.sub', or an exact
        /// relative name (default: '*')
        #[arg(long, value_name = "PATTERN")]
        pattern: Option<String>,
        /// Allowed record types: '*' or a comma-separated list, e.g. 'A,AAAA,TXT'
        /// (default: '*')
        #[arg(long, value_name = "TYPES")]
        types: Option<String>,
    },
    /// List a zone's TSIG policies
    #[command(alias = "ls")]
    List {
        /// The name of the zone
        name: String,
    },
    /// Remove a TSIG policy from a zone by policy ID
    Remove {
        /// The name of the zone
        name: String,
        /// ID of the policy to remove (see `zone tsig-policy list`)
        id: i32,
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

impl ImportMode {
    fn as_str(self) -> &'static str {
        match self {
            ImportMode::Append => "append",
            ImportMode::Upsert => "upsert",
            ImportMode::Replace => "replace",
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
        ZoneCommand::Import {
            name,
            file,
            mode,
            dry_run,
            output,
        } => {
            let content = super::read_input(&file)?;
            let response = client
                .send_command(
                    DaemonCommandKind::ImportZoneFile,
                    Some(json!({
                        "zone_name": name,
                        "content": content,
                        "mode": mode.as_str(),
                        "dry_run": dry_run,
                    })),
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
            print_output_with_table(&response.data, output, |data| {
                data.get("summary")
                    .ok_or("Missing import summary in response".to_string())
                    .and_then(ImportSummaryRow::from_json)
                    .map(|row| vec![row])
            })?;
        }
        ZoneCommand::Snapshot { subcommand } => match subcommand {
            ZoneSnapshotCommand::List {
                name,
                limit,
                offset,
                output,
            } => {
                let data = client
                    .send_command(
                        DaemonCommandKind::ListZoneSnapshots,
                        Some(json!({ "name": name, "limit": limit, "offset": offset })),
                    )
                    .await?
                    .data;

                print_output_with_table(&data, output, |data| {
                    data.get("items")
                        .and_then(|value| value.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| SnapshotRow::from_json(v).ok())
                                .collect()
                        })
                        .ok_or_else(|| "Missing snapshot items in response".to_string())
                })?;
            }
            ZoneSnapshotCommand::Get {
                name,
                serial,
                output,
            } => {
                let data = client
                    .send_command(
                        DaemonCommandKind::GetZoneSnapshot,
                        Some(json!({ "name": name, "serial": serial })),
                    )
                    .await?
                    .data;

                // Table output shows two tables (snapshot, then its records);
                // json/yaml print the whole payload once.
                print_output_with_table(&data, output, |data| {
                    data.get("snapshot")
                        .ok_or("Missing snapshot in response".to_string())
                        .and_then(SnapshotRow::from_json)
                        .map(|row| vec![row])
                })?;
                if output == OutputFormat::Table {
                    print_output_with_table(&data, output, |data| {
                        data.get("records")
                            .and_then(|value| value.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| SnapshotRecordRow::from_json(v).ok())
                                    .collect()
                            })
                            .ok_or_else(|| "Missing records in response".to_string())
                    })?;
                }
            }
        },
        ZoneCommand::Rollback {
            name,
            serial,
            dry_run,
            output,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::RollbackZone,
                    Some(json!({ "name": name, "serial": serial, "dry_run": dry_run })),
                )
                .await?;

            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_output_with_table(&response.data, output, |data| {
                RollbackSummaryRow::from_json(data).map(|row| vec![row])
            })?;
        }
        ZoneCommand::Status { name, output } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneStatus, Some(json!({ "name": name })))
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
                    Some(json!({
                        "zone_name": args.name,
                        "force": args.force
                    })),
                )
                .await?;
            println!("{}", response.message);
        }
        ZoneCommand::TsigPolicy { subcommand } => match subcommand {
            ZoneTsigPolicyCommand::Add {
                name,
                key,
                pattern,
                types,
            } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneTsigPolicyAdd,
                        Some(json!({
                            "zone_name": name,
                            "tsig_key": key,
                            "record_name_pattern": pattern,
                            "record_types": types,
                        })),
                    )
                    .await?;
                println!("{}", response.message);
            }
            ZoneTsigPolicyCommand::List { name } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneTsigPolicyList,
                        Some(json!({ "zone_name": name })),
                    )
                    .await?;
                print_tsig_policies(&response.data)?;
            }
            ZoneTsigPolicyCommand::Remove { name, id } => {
                let response = client
                    .send_command(
                        DaemonCommandKind::ZoneTsigPolicyRemove,
                        Some(json!({ "zone_name": name, "id": id })),
                    )
                    .await?;
                println!("{}", response.message);
            }
        },
    }

    Ok(())
}

fn print_tsig_policies(data: &serde_json::Value) -> Result<(), String> {
    let policies: Vec<crate::api::types::GetZoneTsigPolicyResponse> =
        serde_json::from_value(data.clone())
            .map_err(|e| format!("Failed to parse TSIG policy list response: {}", e))?;

    if policies.is_empty() {
        println!("No TSIG policies found");
        return Ok(());
    }

    println!("TSIG Policies:");
    println!(
        "{:<5} {:<30} {:<20} {:<20}",
        "ID", "TSIG KEY", "NAME PATTERN", "RECORD TYPES"
    );
    println!("{}", "-".repeat(80));

    for policy in policies {
        println!(
            "{:<5} {:<30} {:<20} {:<20}",
            policy.id, policy.tsig_key, policy.record_name_pattern, policy.record_types
        );
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
