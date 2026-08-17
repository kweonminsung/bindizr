//! The `zone snapshot` subcommands: list, show, diff, and rollback.

use bindizr_service::types::{
    PaginatedResponse, RollbackZoneRequest, RollbackZoneResponse, SnapshotDetailResponse,
    SnapshotDiffResponse, ZoneSnapshotResponse,
};
use clap::Subcommand;

use crate::{
    cli::{
        error::CliError,
        output::{
            OutputFormat, RollbackSummaryRow, SnapshotRecordRow, SnapshotRow, parse_response,
            print_response, print_table, render_diff_lines,
        },
    },
    socket::{
        client::DaemonSocketClient,
        types::{
            DaemonCommandKind, DiffZoneSnapshotsParams, ListZoneSnapshotsParams,
            RollbackZoneParams, ZoneSnapshotParams,
        },
    },
};

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
    /// Show the record differences between two serials
    Diff {
        /// The name of the zone
        name: String,
        /// The serial to diff from
        from_serial: i32,
        /// The serial to diff to (omit to compare against the current serial)
        to_serial: Option<i32>,
        /// Output format (json, yaml, table)
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
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
}

pub(super) async fn handle_command(
    client: &DaemonSocketClient,
    subcommand: ZoneSnapshotCommand,
) -> Result<(), CliError> {
    match subcommand {
        ZoneSnapshotCommand::List {
            name,
            limit,
            offset,
            output,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::ListZoneSnapshots,
                    ListZoneSnapshotsParams {
                        name,
                        limit,
                        offset,
                    },
                )
                .await?
                .data;

            print_response(
                &data,
                output,
                |page: &PaginatedResponse<ZoneSnapshotResponse>| {
                    page.items.iter().map(SnapshotRow::from).collect()
                },
            )?;
        }
        ZoneSnapshotCommand::Get {
            name,
            serial,
            output,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::GetZoneSnapshot,
                    ZoneSnapshotParams { name, serial },
                )
                .await?
                .data;

            // Table output shows two tables (snapshot, then its records);
            // json/yaml print the whole payload once.
            if output == OutputFormat::Table {
                let detail: SnapshotDetailResponse = parse_response(&data)?;
                print_table(vec![SnapshotRow::from(&detail.snapshot)]);
                print_table(detail.records.iter().map(SnapshotRecordRow::from).collect());
            } else {
                print_response(&data, output, |detail: &SnapshotDetailResponse| {
                    vec![SnapshotRow::from(&detail.snapshot)]
                })?;
            }
        }
        ZoneSnapshotCommand::Diff {
            name,
            from_serial,
            to_serial,
            output,
        } => {
            let data = client
                .send_command(
                    DaemonCommandKind::DiffZoneSnapshots,
                    DiffZoneSnapshotsParams {
                        name,
                        from_serial,
                        to_serial,
                    },
                )
                .await?
                .data;

            match output {
                OutputFormat::Table => {
                    print!("{}", render_snapshot_diff(&parse_response(&data)?))
                }
                _ => print_response(&data, output, |_: &SnapshotDiffResponse| {
                    Vec::<SnapshotRow>::new()
                })?,
            }
        }
        ZoneSnapshotCommand::Rollback {
            name,
            serial,
            dry_run,
            output,
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

            if output == OutputFormat::Table {
                println!("{}", response.message);
            }
            print_response(&response.data, output, |rollback: &RollbackZoneResponse| {
                vec![RollbackSummaryRow::from(rollback)]
            })?;
        }
    }

    Ok(())
}

/// Render a snapshot diff: the `+`/`-`/`~` lines plus SOA-serial and count footers.
fn render_snapshot_diff(response: &SnapshotDiffResponse) -> String {
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
