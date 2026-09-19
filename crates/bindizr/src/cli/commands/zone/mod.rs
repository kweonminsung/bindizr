//! The `zone` subcommands; the `version` family owns its own grammar,
//! dispatch, and output rendering in a sibling module.

mod version;

use bindizr_core::{errln, out, outln};
use bindizr_service::types::{
    CreateZoneRequest, ExportZoneFileResponse, GetTokenGrantResponse, GetTsigGrantResponse,
    GetZoneResponse, GetZonesFilter, ImportMode as ServiceImportMode, ImportZoneRequest,
    ImportZoneResponse, PageFilter, PaginatedResponse, UpdateZoneRequest, ZoneResponse,
    ZoneStatusResponse,
};
use clap::{Args, Subcommand, ValueEnum};
pub(crate) use version::ZoneVersionCommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            ImportSummaryRow, OutputFormat, SecondaryStatusRow, TokenGrantRow, TsigGrantRow,
            ZoneRow, parse_response, print_payload, print_response, print_table,
            render_change_preview,
        },
    },
    socket::{
        client,
        types::{
            DaemonCommandKind, DeleteZoneParams, ExportZoneFileParams, ImportZoneParams,
            ListGrantsParams, NotifyAllZonesParams, NotifyZoneParams, UpdateZoneParams,
            ZoneNameParams,
        },
    },
};

/// Subcommands for managing zones.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneCommand {
    /// Create a zone
    #[command(after_help = "\
Examples:
  bindizr zone create example.com --mname ns1.example.com --rname admin@example.com
  bindizr zone create example.com --mname ns1.example.com --rname admin@example.com --default-ttl 300

Both name the zone's SOA and neither is guessed: a wrong primary is published,
and the contact is the address a resolver operator writes to.")]
    Create {
        /// Zone name
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// SOA MNAME: the zone's public primary nameserver, usually a BIND secondary (e.g. ns1.example.com)
        #[arg(long)]
        mname: String,
        /// SOA RNAME, as an email address (e.g. admin@example.com)
        #[arg(long)]
        rname: String,
        /// Default record TTL (seconds; defaults to dns.zone_defaults.ttl)
        #[arg(long)]
        default_ttl: Option<i32>,
        /// Starting serial, 1-2137483647 (optional, auto-generated if not provided)
        #[arg(long)]
        serial: Option<i32>,
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
        /// Free-text note for operators
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Validate and report the change without writing it
        #[arg(long)]
        dry_run: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// List zones
    #[command(alias = "ls")]
    List {
        /// Filter by zone name
        #[arg(long, value_name = "ZONE_NAME")]
        name: Option<String>,
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
        /// Filter by minimum serial
        #[arg(long)]
        min_serial: Option<i32>,
        /// Filter by maximum serial
        #[arg(long)]
        max_serial: Option<i32>,
        /// Keep zones created at or after this RFC 3339 timestamp
        #[arg(long, value_name = "TIMESTAMP")]
        created_after: Option<chrono::DateTime<chrono::Utc>>,
        /// Keep zones created at or before this RFC 3339 timestamp
        #[arg(long, value_name = "TIMESTAMP")]
        created_before: Option<chrono::DateTime<chrono::Utc>>,
        /// Keep only zones signing under a DNSSEC policy
        #[arg(long)]
        signed: bool,
        /// Keep the zones the DNS plane serves, or the disabled ones
        #[arg(long, value_name = "true|false")]
        enabled: Option<bool>,
        /// Search zones by partial text
        #[arg(short = 'q', long)]
        search: Option<String>,
        /// Sort by: name (default), serial, default_ttl, created_at
        #[arg(long, value_name = "FIELD")]
        sort: Option<String>,
        /// Sort order: asc (default) or desc
        #[arg(long, value_name = "asc|desc")]
        order: Option<String>,
        /// Maximum number of zones to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of zones to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Get a zone by name
    Get {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Update a zone, changing only the fields you pass
    Update {
        /// The name of the zone to update
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Rename the zone to this name
        #[arg(long, value_name = "ZONE_NAME")]
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
        /// Serve the zone or stop serving it without deleting it
        #[arg(long, value_name = "true|false")]
        enabled: Option<bool>,
        /// Free-text note for operators; empty clears it
        #[arg(long, value_name = "TEXT")]
        description: Option<String>,
        /// Validate and report the change without writing it
        #[arg(long)]
        dry_run: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Delete a zone
    #[command(alias = "rm")]
    Delete {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Report what the delete would take without removing anything
        #[arg(long)]
        dry_run: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Import a BIND zone file into a zone
    #[command(after_help = "\
The file is standard BIND zone file text, for example:
  www    300  IN A   192.0.2.1
  mail        IN A   192.0.2.2
  @           IN MX  10 mail.example.com.

Relative names resolve against the zone and missing TTLs fall back to the
zone TTL. SOA lines are ignored (SOA metadata is managed by bindizr) and
$INCLUDE is not supported.

TTLs are decimal seconds (RFC 1035). A file using BIND's unit suffixes
(1h, 2d) is refused; write it out in seconds first:
  named-compilezone -o - example.com db.example.com")]
    Import {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
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
        /// Parse and validate without applying any change, showing the change
        /// as a +/-/~ diff
        #[arg(long)]
        dry_run: bool,
        /// Pass over record types bindizr does not store instead of failing
        /// the whole file
        #[arg(long)]
        skip_unsupported: bool,
        /// Create the zone from the file's SOA when it does not exist yet
        #[arg(long)]
        create: bool,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Export a zone as BIND master-file text
    #[command(after_help = "\
Examples:
  bindizr zone export example.com > db.example.com
  bindizr zone export example.com --signed > db.example.com.signed

--signed appends the derived DNSSEC records (RRSIG, DNSKEY, NSEC/NSEC3), which
bindizr generates rather than stores as editable records.")]
    Export {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Append the derived DNSSEC records; for inspection, not re-import
        #[arg(long)]
        signed: bool,
    },

    /// Show how far each secondary has caught up with a zone
    Status {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Send NOTIFY messages to secondary servers for a zone, or for every zone
    #[command(after_help = "\
Examples:
  bindizr zone notify example.com
  bindizr zone notify                 # every zone
  bindizr zone notify --bump-serial   # every zone, transferring even where nothing changed")]
    Notify(NotifyArgs),

    /// List the API token grants that apply to a zone
    TokenGrants {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Maximum number of grants to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of grants to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// List the TSIG key grants that apply to a zone
    TsigGrants {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Maximum number of grants to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of grants to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
        output: OutputFormat,
    },

    /// Inspect or roll back a zone's versions (serial history)
    Version {
        #[command(subcommand)]
        subcommand: ZoneVersionCommand,
    },
}

/// How `zone import` reconciles parsed records with the records already in the
/// zone. Mirrors the service-layer `ImportMode`; serialized as its lowercase
/// wire name.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ImportMode {
    /// Add parsed records; records already present are left untouched
    Append,
    /// Replace the records of every name and type that appears in the file
    Upsert,
    /// Replace all non-protected records in the zone
    Replace,
}

impl From<ImportMode> for ServiceImportMode {
    /// Convert the CLI import mode into the service import mode.
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
    /// The name of the zone; omit it to notify every zone
    #[arg(value_name = "ZONE_NAME")]
    name: Option<String>,

    /// Bump the serial first, so secondaries transfer even when nothing
    /// changed
    #[arg(long)]
    bump_serial: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table)]
    output: OutputFormat,
}

/// Handle the `zone` subcommand by forwarding it to the daemon over the socket.
pub(crate) async fn handle_command(subcommand: ZoneCommand) -> Result<(), CliError> {
    match subcommand {
        ZoneCommand::Create {
            name,
            mname,
            rname,
            default_ttl,
            serial,
            refresh,
            retry,
            expire,
            minimum_ttl,
            description,
            dry_run,
            output,
        } => {
            let data = client::send_command(
                DaemonCommandKind::CreateZone,
                CreateZoneRequest {
                    dry_run,
                    name,
                    mname,
                    rname,
                    default_ttl,
                    serial,
                    description,
                    refresh,
                    retry,
                    expire,
                    minimum_ttl,
                },
            )
            .await?
            .data;

            print_response(&data, output, |response: &ZoneResponse| {
                vec![ZoneRow::from(&response.zone)]
            })?;
        }
        ZoneCommand::List {
            name,
            mname,
            rname,
            default_ttl,
            min_default_ttl,
            max_default_ttl,
            serial,
            min_serial,
            max_serial,
            created_after,
            created_before,
            signed,
            enabled,
            search,
            sort,
            order,
            limit,
            offset,
            output,
        } => {
            let has_filters = name.is_some()
                || mname.is_some()
                || rname.is_some()
                || default_ttl.is_some()
                || min_default_ttl.is_some()
                || max_default_ttl.is_some()
                || serial.is_some()
                || min_serial.is_some()
                || max_serial.is_some()
                || created_after.is_some()
                || created_before.is_some()
                || signed
                || enabled.is_some()
                || search.is_some()
                || sort.is_some()
                || order.is_some()
                || limit.is_some()
                || offset.is_some();
            let filter_payload = || GetZonesFilter {
                name,
                // The HTTP API keeps an id filter; the CLI keys zones by name,
                // which is UNIQUE, so it never sends one.
                id: None,
                mname,
                rname,
                default_ttl,
                min_default_ttl,
                max_default_ttl,
                serial,
                min_serial,
                max_serial,
                created_after,
                created_before,
                signed: signed.then_some(true),
                enabled,
                search,
                sort,
                order,
                limit,
                offset,
            };
            let data = client::send_command(
                DaemonCommandKind::ListZones,
                has_filters.then(filter_payload),
            )
            .await?
            .data;

            print_response(
                &data,
                output,
                |page: &PaginatedResponse<GetZoneResponse>| {
                    page.items.iter().map(ZoneRow::from).collect()
                },
            )?;
        }
        ZoneCommand::Get { name, output } => {
            let data = client::send_command(DaemonCommandKind::GetZone, ZoneNameParams { name })
                .await?
                .data;

            match output {
                OutputFormat::Table => {
                    let response: ZoneResponse = parse_response(&data)?;
                    print_table(vec![ZoneRow::from(&response.zone)]);
                }
                _ => print_payload(&data, output)?,
            }
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
            enabled,
            description,
            dry_run,
            output,
        } => {
            let data = client::send_command(
                DaemonCommandKind::UpdateZone,
                // `name` looks up the zone; `new_name` renames it.
                UpdateZoneParams {
                    zone_name: name,
                    request: UpdateZoneRequest {
                        dry_run,
                        name: new_name,
                        mname,
                        rname,
                        default_ttl,
                        refresh,
                        retry,
                        expire,
                        minimum_ttl,
                        serial: None,
                        enabled,
                        description,
                    },
                },
            )
            .await?
            .data;

            print_response(&data, output, |response: &ZoneResponse| {
                vec![ZoneRow::from(&response.zone)]
            })?;
        }
        ZoneCommand::Delete {
            name,
            dry_run,
            output,
        } => {
            let response = client::send_command(
                DaemonCommandKind::DeleteZone,
                DeleteZoneParams { name, dry_run },
            )
            .await?;
            match output {
                OutputFormat::Table => outln!("{}", response.message),
                _ => print_payload(&response.data, output)?,
            }
        }
        ZoneCommand::Export { name, signed } => {
            let data = client::send_command(
                DaemonCommandKind::ExportZone,
                ExportZoneFileParams { name, signed },
            )
            .await?
            .data;
            let export: ExportZoneFileResponse = parse_response(&data)?;
            out!("{}", export.zone_file);
        }
        ZoneCommand::Import {
            name,
            file,
            from_server,
            mode,
            dry_run,
            skip_unsupported,
            create,
            output,
        } => {
            let content = file.map(|file| super::read_input(&file)).transpose()?;
            let response = client::send_command(
                DaemonCommandKind::ImportZone,
                ImportZoneParams {
                    zone_name: name,
                    request: ImportZoneRequest {
                        content,
                        from_server,
                        mode: mode.into(),
                        dry_run,
                        skip_unsupported,
                        create,
                    },
                },
            )
            .await?;

            let import: ImportZoneResponse = parse_response(&response.data)?;
            match output {
                OutputFormat::Table => {
                    outln!("{}", response.message);

                    // Diagnostics go to stderr, so a pipeline keeps the summary clean.
                    for error in &import.errors {
                        errln!("  - {}", error);
                    }
                    for skipped in &import.skipped_records {
                        errln!("  ~ {}", skipped);
                    }

                    print_table(vec![ImportSummaryRow::from(&import)]);
                    if dry_run {
                        out!("{}", render_change_preview(&import.diff));
                    }
                }
                _ => print_payload(&response.data, output)?,
            }

            // A rejected import applied nothing, so it must not exit as a success.
            if import.was_rejected() {
                return Err(CliError::from(format!(
                    "import rejected: {} record(s) failed validation; nothing was applied",
                    import.errors.len()
                )));
            }
        }
        ZoneCommand::Version { subcommand } => version::handle_command(subcommand).await?,
        ZoneCommand::Status { name, output } => {
            let response =
                client::send_command(DaemonCommandKind::GetZoneStatus, ZoneNameParams { name })
                    .await?;

            if output != OutputFormat::Table {
                print_payload(&response.data, output)?;
                return Ok(());
            }
            let status: ZoneStatusResponse = parse_response(&response.data)?;
            outln!("Zone {} (serial {})", status.zone, status.serial);
            if status.secondaries.is_empty() {
                outln!("No secondaries configured.");
                return Ok(());
            }
            print_table(SecondaryStatusRow::rows_from_status(&status));
        }
        ZoneCommand::TokenGrants {
            name,
            limit,
            offset,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::ListZoneTokenGrants,
                ListGrantsParams {
                    name,
                    page: PageFilter { limit, offset },
                },
            )
            .await?;
            print_response(
                &res.data,
                output,
                |grants: &PaginatedResponse<GetTokenGrantResponse>| {
                    grants.items.iter().map(TokenGrantRow::from).collect()
                },
            )?;
        }
        ZoneCommand::TsigGrants {
            name,
            limit,
            offset,
            output,
        } => {
            let res = client::send_command(
                DaemonCommandKind::ListZoneTsigGrants,
                ListGrantsParams {
                    name,
                    page: PageFilter { limit, offset },
                },
            )
            .await?;
            print_response(
                &res.data,
                output,
                |grants: &PaginatedResponse<GetTsigGrantResponse>| {
                    grants.items.iter().map(TsigGrantRow::from).collect()
                },
            )?;
        }
        ZoneCommand::Notify(args) => {
            // The daemon has a command for each.
            let response = match args.name {
                Some(zone_name) => {
                    client::send_command(
                        DaemonCommandKind::NotifyZone,
                        NotifyZoneParams {
                            zone_name,
                            bump_serial: args.bump_serial,
                        },
                    )
                    .await?
                }
                None => {
                    client::send_command(
                        DaemonCommandKind::NotifyAllZones,
                        NotifyAllZonesParams {
                            bump_serial: args.bump_serial,
                        },
                    )
                    .await?
                }
            };
            match args.output {
                OutputFormat::Table => outln!("{}", response.message),
                _ => print_payload(&response.data, args.output)?,
            }
        }
    }

    Ok(())
}
