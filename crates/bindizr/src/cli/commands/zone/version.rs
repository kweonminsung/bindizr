//! The `zone version` subcommands: list, show, diff, and rollback.

use bindizr_service::types::{
    PaginatedResponse, RollbackZoneRequest, RollbackZoneResponse, VersionDetailResponse,
    VersionDiffResponse, ZoneVersionResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            OutputFormat, RollbackSummaryRow, VersionRecordRow, VersionRow, parse_response,
            print_payload, print_response, print_table, render_diff_lines,
        },
    },
    socket::{
        client::DaemonSocketClient,
        types::{
            DaemonCommandKind, DiffZoneVersionsParams, ListZoneVersionsParams, RollbackZoneParams,
            ZoneVersionParams,
        },
    },
};

/// Subcommands for inspecting a zone's versions.
#[derive(Subcommand, Debug)]
pub(crate) enum ZoneVersionCommand {
    /// List a zone's versions (serial history)
    #[command(alias = "ls")]
    List {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Maximum number of versions to return
        #[arg(long)]
        limit: Option<u32>,
        /// Number of versions to skip
        #[arg(long)]
        offset: Option<u64>,
        /// Include signer-only serials (DNSSEC re-signs and rollovers)
        #[arg(long)]
        all: bool,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Show the zone state captured at one version serial
    Get {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Version serial to inspect
        serial: i32,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Show the record differences between two serials
    Diff {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// The serial to diff from
        from_serial: i32,
        /// The serial to diff to (omit to compare against the current serial)
        to_serial: Option<i32>,
    },
    /// Roll a zone back to the state captured at a version serial
    Rollback {
        /// The name of the zone
        #[arg(value_name = "ZONE_NAME")]
        name: String,
        /// Target version serial (the zone serial still advances)
        serial: i32,
        /// Compute and report the rollback without applying any change
        #[arg(long)]
        dry_run: bool,
    },
}

pub(crate) async fn handle_command(
    client: &DaemonSocketClient,
    subcommand: ZoneVersionCommand,
) -> Result<(), CliError> {
    match subcommand {
        ZoneVersionCommand::List {
            name,
            limit,
            offset,
            all,
            output,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::ListZoneVersions,
                    ListZoneVersionsParams {
                        name,
                        limit,
                        offset,
                        all,
                    },
                )
                .await?
                .data;

            print_response(
                &data,
                output,
                |page: &PaginatedResponse<ZoneVersionResponse>| {
                    page.items.iter().map(VersionRow::from).collect()
                },
            )?;
        }
        ZoneVersionCommand::Get {
            name,
            serial,
            output,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::GetZoneVersion,
                    ZoneVersionParams { name, serial },
                )
                .await?
                .data;

            match output {
                OutputFormat::Table => {
                    let detail: VersionDetailResponse = parse_response(&data)?;
                    print_table(vec![VersionRow::from(&detail.version)]);
                    print_table(detail.records.iter().map(VersionRecordRow::from).collect());
                }
                _ => print_payload(&data, output)?,
            }
        }
        ZoneVersionCommand::Diff {
            name,
            from_serial,
            to_serial,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::DiffZoneVersions,
                    DiffZoneVersionsParams {
                        name,
                        from_serial,
                        to_serial,
                    },
                )
                .await?
                .data;

            print!("{}", render_version_diff(&parse_response(&data)?));
        }
        ZoneVersionCommand::Rollback {
            name,
            serial,
            dry_run,
        } => {
            let response = client
                .send_command(
                    DaemonCommandKind::RollbackZone,
                    RollbackZoneParams {
                        name,
                        request: RollbackZoneRequest { serial, dry_run },
                    },
                )
                .await?;

            let rollback: RollbackZoneResponse = parse_response(&response.data)?;
            println!("{}", response.message);
            print_table(vec![RollbackSummaryRow::from(&rollback)]);
        }
    }

    Ok(())
}

/// Render a version diff: the `+`/`-`/`~` lines plus SOA-serial and count footers.
fn render_version_diff(response: &VersionDiffResponse) -> String {
    let mut out = render_diff_lines(&response.diff.entries);
    let summary = &response.diff.summary;

    out.push('\n');
    out.push_str(&format!(
        "SOA serial: {} -> {}\n",
        response.from_serial, response.to_serial
    ));
    out.push_str(&format!(
        "Records: +{} -{} ~{}\n",
        summary.added, summary.removed, summary.changed
    ));
    out
}
