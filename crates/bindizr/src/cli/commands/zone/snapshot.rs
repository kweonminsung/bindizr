//! The `zone snapshot` subcommands: list, show, diff, and rollback.

use clap::Subcommand;

use crate::{
    api::types::RollbackZoneRequest,
    cli::{
        error::CliError,
        output::{
            OutputFormat, RollbackSummaryRow, SnapshotRecordRow, SnapshotRow,
            print_output_with_table, render_diff_lines,
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
                    ZoneSnapshotParams { name, serial },
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
                OutputFormat::Table => print!("{}", render_snapshot_diff(&data)),
                _ => print_output_with_table(&data, output, |_| {
                    Ok::<Vec<SnapshotRow>, String>(Vec::new())
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
            print_output_with_table(&response.data, output, |data| {
                RollbackSummaryRow::from_json(data).map(|row| vec![row])
            })?;
        }
    }

    Ok(())
}

/// Render a snapshot diff: the `+`/`-`/`~` lines plus SOA-serial and count footers.
fn render_snapshot_diff(data: &serde_json::Value) -> String {
    let empty = vec![];
    let entries = data
        .get("diff")
        .and_then(|d| d.get("entries"))
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut out = render_diff_lines(entries);

    let serial = |field: &str| data.get(field).and_then(|v| v.as_i64()).unwrap_or(0);
    let count = |field: &str| {
        data.get("diff")
            .and_then(|d| d.get("summary"))
            .and_then(|s| s.get(field))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    out.push('\n');
    out.push_str(&format!(
        "SOA serial: {} -> {}\n",
        serial("from_serial"),
        serial("to_serial")
    ));
    out.push_str(&format!(
        "Records: +{} -{} ~{}\n",
        count("added"),
        count("removed"),
        count("changed")
    ));
    out
}
