//! The `zone` subcommands. Each nested family owns its own grammar, dispatch,
//! and output rendering in a sibling module.

mod dnssec;
mod token_policy;
mod tsig_policy;
mod version;

use bindizr_service::types::{
    CreateZoneRequest, ExportZoneFileResponse, GetZoneResponse, GetZonesFilter,
    ImportMode as ServiceImportMode, ImportZoneFileRequest, ImportZoneFileResponse,
    NotifyZoneRequest, UpdateZonePatch, ZoneStatusResponse,
};
use clap::{Args, Subcommand, ValueEnum};
pub(crate) use dnssec::ZoneDnssecCommand;
pub(crate) use token_policy::ZoneTokenPolicyCommand;
pub(crate) use tsig_policy::ZoneTsigPolicyCommand;
pub(crate) use version::ZoneVersionCommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            ImportSummaryRow, ItemOrPage, OutputFormat, SecondaryStatusRow, ZoneRow,
            parse_response, print_response, print_table, render_change_preview,
        },
    },
    socket::{
        client::DaemonSocketClient,
        types::{
            DaemonCommandKind, ExportZoneFileParams, ImportZoneFileParams, UpdateZoneParams,
            ZoneNameParams,
        },
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
        /// SOA MNAME (primary name server)
        #[arg(long)]
        mname: String,
        /// SOA RNAME, as an email address
        #[arg(long)]
        rname: String,
        /// Default record TTL (seconds)
        #[arg(long)]
        default_ttl: i32,
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
        /// SOA MNAME (primary name server)
        #[arg(long)]
        mname: Option<String>,
        /// SOA RNAME, as an email address
        #[arg(long)]
        rname: Option<String>,
        /// Default record TTL (seconds)
        #[arg(long)]
        default_ttl: Option<i32>,
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
        /// Filter by mname
        #[arg(long)]
        mname: Option<String>,
        /// Filter by rname
        #[arg(long)]
        rname: Option<String>,
        /// Filter by default TTL
        #[arg(long)]
        default_ttl: Option<i32>,
        /// Filter by minimum default TTL
        #[arg(long)]
        min_default_ttl: Option<i32>,
        /// Filter by maximum default TTL
        #[arg(long)]
        max_default_ttl: Option<i32>,
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
    #[command(alias = "rm")]
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
        #[arg(
            required_unless_present = "from_server",
            conflicts_with = "from_server"
        )]
        file: Option<String>,
        /// Pull the records over AXFR from this server (host[:port], port 53
        /// default) instead of a file
        #[arg(long, value_name = "SERVER")]
        from_server: Option<String>,
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
        /// Append the derived DNSSEC records; for inspection, not re-import
        #[arg(long)]
        signed: bool,
    },

    /// Inspect or roll back a zone's versions (serial history)
    Version {
        #[command(subcommand)]
        subcommand: ZoneVersionCommand,
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

    /// Manage a zone's DNSSEC signing (keys, DS records, re-signing)
    Dnssec {
        #[command(subcommand)]
        subcommand: ZoneDnssecCommand,
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
    /// Bump the serial first, so secondaries transfer even when nothing
    /// changed
    #[arg(long)]
    bump_serial: bool,

    /// Zone name to notify (optional: if not specified, notifies all zones)
    name: Option<String>,
}

/// Handle the `zone` subcommand by forwarding it to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: ZoneCommand) -> Result<(), CliError> {
    let client = DaemonSocketClient::new();

    match subcommand {
        ZoneCommand::Create {
            name,
            mname,
            rname,
            default_ttl,
            serial,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::CreateZone,
                    CreateZoneRequest {
                        name,
                        mname,
                        rname,
                        default_ttl,
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
            mname,
            rname,
            default_ttl,
            min_default_ttl,
            max_default_ttl,
            serial,
            search,
            limit,
            offset,
            output,
        } => {
            let has_filters = name.is_some()
                || id.is_some()
                || mname.is_some()
                || rname.is_some()
                || default_ttl.is_some()
                || min_default_ttl.is_some()
                || max_default_ttl.is_some()
                || serial.is_some()
                || search.is_some()
                || limit.is_some()
                || offset.is_some();
            let filter_payload = || GetZonesFilter {
                name,
                id,
                mname,
                rname,
                default_ttl,
                min_default_ttl,
                max_default_ttl,
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
            mname,
            rname,
            default_ttl,
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
                            mname,
                            rname,
                            default_ttl,
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
        ZoneCommand::Export { name, signed } => {
            let data = client
                .send_command(
                    DaemonCommandKind::ExportZoneFile,
                    ExportZoneFileParams { name, signed },
                )
                .await?
                .data;
            let export: ExportZoneFileResponse = parse_response(&data)?;
            print!("{}", export.zone_file);
        }
        ZoneCommand::Import {
            name,
            file,
            from_server,
            mode,
            dry_run,
            preview,
            output,
        } => {
            let content = match &file {
                Some(file) => Some(super::read_input(file)?),
                None => None,
            };
            let response = client
                .send_command(
                    DaemonCommandKind::ImportZoneFile,
                    ImportZoneFileParams {
                        zone_name: name,
                        request: ImportZoneFileRequest {
                            content,
                            from_server,
                            mode: mode.into(),
                            // Preview never applies; it is a dry run rendered as a diff.
                            dry_run: dry_run || preview,
                        },
                    },
                )
                .await?;

            if output == OutputFormat::Table {
                let import: ImportZoneFileResponse = parse_response(&response.data)?;
                if import.errors.is_empty() {
                    println!("{}", response.message);
                } else {
                    eprintln!("{}", response.message);
                    for error in &import.errors {
                        eprintln!("  - {}", error);
                    }
                }

                if preview {
                    print!("{}", render_change_preview(&import.diff.entries));
                    return Ok(());
                }
            }

            print_response(&response.data, output, |import: &ImportZoneFileResponse| {
                vec![ImportSummaryRow::from(&import.summary)]
            })?;
        }
        ZoneCommand::Version { subcommand } => version::handle_command(&client, subcommand).await?,
        ZoneCommand::Status { name, output } => {
            let response = client
                .send_command(DaemonCommandKind::ZoneStatus, ZoneNameParams { name })
                .await?;

            if output == OutputFormat::Table {
                let status: ZoneStatusResponse = parse_response(&response.data)?;
                println!("Zone {} (serial {})", status.zone, status.serial);
                if status.secondaries.is_empty() {
                    println!("No secondaries configured.");
                    return Ok(());
                }
                print_table(SecondaryStatusRow::rows_from_status(&status));
                return Ok(());
            }
            print_response(&response.data, output, |status: &ZoneStatusResponse| {
                SecondaryStatusRow::rows_from_status(status)
            })?;
        }
        ZoneCommand::Notify(args) => {
            let response = client
                .send_command(
                    DaemonCommandKind::NotifyZone,
                    NotifyZoneRequest {
                        zone_name: args.name,
                        bump_serial: args.bump_serial,
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
        ZoneCommand::Dnssec { subcommand } => dnssec::handle_command(&client, subcommand).await?,
    }

    Ok(())
}

fn print_zones(data: &serde_json::Value, output: OutputFormat) -> Result<(), String> {
    print_response(data, output, |zones: &ItemOrPage<GetZoneResponse>| {
        zones.items().iter().map(ZoneRow::from).collect()
    })
}
